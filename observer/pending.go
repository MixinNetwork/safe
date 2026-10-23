package observer

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/shopspring/decimal"
)

const bitcoinPendingDepositGracePeriod = time.Minute * 5
const ethereumPendingDepositTTL = 24 * time.Hour

func (node *Node) listPendingDeposits(ctx context.Context, chain byte, holder string, offset int64) ([]*PendingDeposit, error) {
	deposits, err := node.store.ListPendingDeposits(ctx, int(chain), holder, offset)
	if err != nil {
		return nil, err
	}
	type depositKey struct {
		hash  string
		index int64
	}
	seen := make(map[depositKey]bool, len(deposits))
	for _, d := range deposits {
		seen[depositKey{d.TransactionHash, d.OutputIndex}] = true
	}

	var after *Deposit
	for added := 0; added < 100; {
		initial, err := node.store.listInitialDepositsByCreatedAt(ctx, int(chain), holder, offset, after)
		if err != nil {
			return nil, err
		}
		var sent map[string]string
		switch chain {
		case common.SafeChainBitcoin, common.SafeChainLitecoin:
			sent, err = node.store.QueryDepositSentHashes(ctx, initial)
			if err != nil {
				return nil, err
			}
		}
		for _, d := range initial {
			key := depositKey{d.TransactionHash, d.OutputIndex}
			if seen[key] {
				continue
			}
			switch chain {
			case common.SafeChainBitcoin, common.SafeChainLitecoin:
				if node.bitcoinCheckDepositChange(ctx, d.TransactionHash, d.OutputIndex, sent[d.TransactionHash]) {
					continue
				}
			}
			deposits = append(deposits, &PendingDeposit{
				TransactionHash: d.TransactionHash, OutputIndex: d.OutputIndex,
				AssetId: d.AssetId, AssetAddress: d.AssetAddress, Amount: d.Amount,
				Receiver: d.Receiver, Sender: d.Sender, State: d.State,
				Chain: d.Chain, Holder: d.Holder, CreatedAt: d.CreatedAt,
			})
			seen[key] = true
			added++
			if added == 100 {
				break
			}
		}
		if len(initial) < 100 {
			break
		}
		after = initial[len(initial)-1]
	}
	sort.Slice(deposits, func(i, j int) bool {
		a, b := deposits[i], deposits[j]
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		if a.TransactionHash != b.TransactionHash {
			return a.TransactionHash < b.TransactionHash
		}
		return a.OutputIndex < b.OutputIndex
	})
	if len(deposits) > 100 {
		deposits = deposits[:100]
	}
	return deposits, nil
}

func (node *Node) bitcoinPendingDepositsLoop(ctx context.Context, chain byte) {
	seen := make(map[string]bool)
	for {
		time.Sleep(5 * time.Second)
		err := node.scanBitcoinPendingDeposits(ctx, chain, seen)
		logger.Printf("node.scanBitcoinPendingDeposits(%d) => %v", chain, err)
	}
}

func (node *Node) scanBitcoinPendingDeposits(ctx context.Context, chain byte, seen map[string]bool) error {
	rpc, _, _ := node.bitcoinParams(chain)
	hashes, err := bitcoin.RPCGetRawMempoolHashes(rpc)
	logger.Printf("bitcoin.RPCGetRawMempoolHashes(%d) => %d %v", chain, len(hashes), err)
	if err != nil {
		return fmt.Errorf("bitcoin.RPCGetRawMempoolHashes(%d) => %w", chain, err)
	}
	mempool := make(map[string]bool, len(hashes))
	for _, hash := range hashes {
		mempool[hash] = true
	}
	for hash := range seen {
		if !mempool[hash] {
			delete(seen, hash)
		}
	}

	// Use persisted observations, including those recorded before a restart.
	err = node.reconcileBitcoinPendingDeposits(ctx, chain, mempool, time.Now().UTC())
	if err != nil {
		return err
	}

	for _, hash := range hashes {
		if seen[hash] {
			continue
		}
		tx, err := bitcoin.RPCGetTransaction(chain, rpc, hash)
		if err != nil {
			return fmt.Errorf("bitcoin.RPCGetTransaction(%s) => %v %v", hash, tx, err)
		}
		if tx == nil {
			logger.Printf("bitcoin.RPCGetTransaction(%s) => %v %v", hash, tx, err)
			continue
		}
		err = node.bitcoinRecordPendingTransaction(ctx, tx, chain)
		if err != nil {
			return err
		}
		seen[hash] = true
	}
	return nil
}

func (node *Node) reconcileBitcoinPendingDeposits(ctx context.Context, chain byte, mempool map[string]bool, now time.Time) error {
	observations, err := node.store.listPendingDepositObservations(ctx, chain)
	if err != nil {
		return err
	}
	rpc, _, _ := node.bitcoinParams(chain)
	// One RPC per transaction even when it has several Safe outputs.
	lookups := make(map[string]bool)
	for _, d := range observations {
		if mempool[d.TransactionHash] {
			if d.MissingSince.Valid {
				err := node.store.updatePendingDepositMissingSince(ctx, chain, d, sql.NullTime{})
				if err != nil {
					return err
				}
			}
			continue
		}
		if !d.MissingSince.Valid {
			err := node.store.updatePendingDepositMissingSince(ctx, chain, d, sql.NullTime{Time: now, Valid: true})
			if err != nil {
				return err
			}
			continue
		}
		if now.Before(d.MissingSince.Time.Add(bitcoinPendingDepositGracePeriod)) {
			continue
		}
		found, checked := lookups[d.TransactionHash]
		if !checked {
			tx, err := bitcoin.RPCGetTransaction(chain, rpc, d.TransactionHash)
			logger.Printf("reconcile pending bitcoin transaction(%d, %s) => %v %v", chain, d.TransactionHash, tx, err)
			if err != nil {
				return fmt.Errorf("bitcoin.RPCGetTransaction(%s) => %w", d.TransactionHash, err)
			}
			// With the required txindex=1, only a definitive not-found response
			// permits deletion. Mined transactions stay pending.
			found = tx != nil
			lookups[d.TransactionHash] = found
		}
		if found {
			// A transaction may reappear after the snapshot. Any later
			// disappearance must receive a fresh grace period.
			err := node.store.updatePendingDepositMissingSince(ctx, chain, d, sql.NullTime{})
			if err != nil {
				return err
			}
		} else {
			err := node.store.deleteMissingPendingDeposit(ctx, chain, d)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (node *Node) bitcoinRecordPendingTransaction(ctx context.Context, tx *bitcoin.RPCTransaction, chain byte) error {
	for _, index := range bitcoinDepositOutputIndexes(tx) {
		out := tx.Vout[index]
		err := node.bitcoinRecordPendingDeposit(ctx, out.ScriptPubKey.Address, tx, out.N, out.Value, chain)
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) bitcoinRecordPendingDeposit(ctx context.Context, receiver string, tx *bitcoin.RPCTransaction, index int64, value float64, chain byte) error {
	if len(tx.Vin) == 0 {
		return fmt.Errorf("missing transaction inputs %s", tx.TxId)
	}

	rpc, chainId, params := node.bitcoinParams(chain)
	amount := decimal.NewFromFloat(value)
	minimum := decimal.RequireFromString(params.TransactionMinimum)

	sent, err := node.store.QueryDepositSentHashes(ctx, []*Deposit{{TransactionHash: tx.TxId}})
	logger.Verbosef("store.QueryDepositSentHashes(%s) => %v %v", tx.TxId, sent, err)
	if err != nil {
		return fmt.Errorf("store.QueryDepositSentHashes(%s) => %v", tx.TxId, err)
	}
	change := node.bitcoinCheckDepositChange(ctx, tx.TxId, index, sent[tx.TxId])
	if change || amount.Cmp(minimum) < 0 {
		return nil
	}

	old, _, err := node.keeperStore.ReadBitcoinUTXO(ctx, tx.TxId, int(index))
	logger.Verbosef("keeperStore.ReadBitcoinUTXO(%s, %d) => %v %v", tx.TxId, index, old, err)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadBitcoinUTXO(%s, %d) => %v", tx.TxId, index, err)
	} else if old != nil {
		return nil
	}

	safe, err := node.keeperStore.ReadSafeByAddress(ctx, receiver)
	logger.Verbosef("keeperStore.ReadSafeByAddress(%s) => %v %v", receiver, safe, err)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadSafeByAddress(%s) => %v", receiver, err)
	} else if safe == nil || safe.Chain != chain || safe.State != common.RequestStateDone {
		return nil
	}

	c, err := node.keeperStore.ReadUnspentUtxoCountForSafe(ctx, receiver)
	logger.Verbosef("keeperStore.ReadUnspentUtxoCountForSafe(%s) => %d %v", receiver, c, err)
	if err != nil || c >= bitcoin.MaxUnspentUtxo/2 {
		return err
	}

	createdAt := time.Now().UTC()
	deposit := &PendingDeposit{
		TransactionHash: tx.TxId,
		OutputIndex:     index,
		AssetId:         chainId,
		Amount:          amount.String(),
		Receiver:        receiver,
		State:           common.RequestStateInitial,
		Chain:           chain,
		Holder:          safe.Holder,
		CreatedAt:       createdAt,
	}

	sender, err := bitcoin.RPCGetTransactionSender(chain, rpc, tx)
	if err != nil {
		return fmt.Errorf("bitcoin.RPCGetTransactionSender(%s) => %v", tx.TxId, err)
	}
	deposit.Sender = sender

	err = node.store.WritePendingDepositRecord(ctx, deposit)
	if err != nil {
		return fmt.Errorf("store.WritePendingDepositRecord(%v) => %v", deposit, err)
	}
	return nil
}

func (node *Node) ethereumPendingDepositsLoop(ctx context.Context, chain byte) {
	for {
		time.Sleep(time.Second)
		err := node.scanEthereumPendingDeposits(ctx, chain)
		logger.Printf("node.scanEthereumPendingDeposits(%d) => %v", chain, err)
	}
}

func (node *Node) scanEthereumPendingDeposits(ctx context.Context, chain byte) error {
	// Expire observations even when the head is unchanged or RPC is unavailable.
	// Formal deposits are processed independently by the block loop.
	err := node.store.deleteExpiredEthereumPendingDeposits(ctx, chain, time.Now().UTC().Add(-ethereumPendingDepositTTL))
	if err != nil {
		return err
	}
	rpc, _, _ := node.ethereumParams(chain)
	duration := 5 * time.Second
	switch chain {
	case common.SafeChainPolygon:
		duration = 2 * time.Second
	case common.SafeChainEthereum:
	}

	checkpoint, err := node.readPendingDepositCheckpoint(ctx, chain)
	if err != nil {
		return err
	}
	height, err := ethereum.RPCGetBlockHeight(rpc)
	if err != nil {
		logger.Printf("ethereum.RPCGetBlockHeight(%d) => %v", chain, err)
		return nil
	}
	logger.Printf("node.readPendingDepositCheckpoint(%d) => %d %d", chain, checkpoint, height)
	if checkpoint >= height {
		time.Sleep(duration)
		return nil
	}
	end := min(height, checkpoint+node.getChainBlockBatch(chain))
	for current := checkpoint + 1; current <= end; current++ {
		err := node.ethereumRecordPendingBlock(ctx, current, chain)
		logger.Printf("node.ethereumRecordPendingBlock(%d, %d) => %v", chain, current, err)
		if err != nil {
			return err
		}
		err = node.store.WriteProperty(ctx, pendingDepositCheckpointKey(chain), fmt.Sprint(current))
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) ethereumRecordPendingBlock(ctx context.Context, height int64, chain byte) error {
	transfers, err := node.ethereumReadPendingBlockTransfers(ctx, height, chain)
	if err != nil {
		return err
	}
	for _, transfer := range transfers {
		err := node.ethereumRecordPendingTransfer(ctx, transfer, chain)
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) ethereumReadPendingBlockTransfers(ctx context.Context, height int64, chain byte) ([]*ethereum.Transfer, error) {
	rpc, assetID, _ := node.ethereumParams(chain)
	block, err := ethereum.RPCGetBlockWithTransactions(rpc, height)
	if err != nil {
		return nil, err
	}
	if block.Hash == "" || int64(block.Height) != height {
		return nil, fmt.Errorf("invalid pending block at %d", height)
	}
	// Bind execution results to the transaction list, even if this height reorgs.
	traces, err := ethereum.RPCDebugTraceBlockByHash(rpc, block.Hash)
	if err != nil {
		return nil, err
	}
	if len(traces) > len(block.Tx) || (chain != common.SafeChainPolygon && len(traces) != len(block.Tx)) {
		return nil, fmt.Errorf("pending block trace count mismatch at %d", height)
	}
	for i, trace := range traces {
		if block.Tx[i] == nil || block.Tx[i].Hash == "" || (trace.TxHash != "" && trace.TxHash != block.Tx[i].Hash) {
			return nil, fmt.Errorf("pending block trace transaction mismatch at %d", height)
		}
	}
	logs, err := ethereum.GetERC20TransferLogFromBlockHash(ctx, rpc, int64(chain), block.Hash)
	if err != nil {
		return nil, err
	}
	// Reject a branch change observed during the reads before interpreting transfers.
	current, err := ethereum.RPCGetBlockByHeight(rpc, height)
	if err != nil {
		return nil, err
	}
	if current.Hash != block.Hash || current.Height != block.Height {
		return nil, fmt.Errorf("pending block changed while reading at %d", height)
	}
	return append(ethereum.LoopBlockTraces(chain, assetID, traces, block), logs...), nil
}

func (node *Node) ethereumRecordPendingTransfer(ctx context.Context, transfer *ethereum.Transfer, chain byte) error {
	if transfer.Value == nil || transfer.Value.Sign() <= 0 || transfer.Receiver == ethereum.EthereumEmptyAddress {
		return nil
	}
	_, _, params := node.ethereumParams(chain)
	minimum := decimal.RequireFromString(params.TransactionMinimum)
	old, err := node.keeperStore.ReadDeposit(ctx, transfer.Hash, transfer.Index)
	logger.Printf("keeperStore.ReadDeposit(%s, %d, %s, %s) => %v %v", transfer.Hash, transfer.Index, transfer.AssetId, transfer.Receiver, old, err)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadDeposit(%s, %d, %s, %s) => %v %v", transfer.Hash, transfer.Index, transfer.AssetId, transfer.Receiver, old, err)
	} else if old != nil {
		return nil
	}
	safe, err := node.keeperStore.ReadSafeByAddress(ctx, transfer.Receiver)
	logger.Printf("keeperStore.ReadSafeByAddress(%s, %s) => %v %v", transfer.Hash, transfer.Receiver, safe, err)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadSafeByAddress(%s) => %v", transfer.Receiver, err)
	} else if safe == nil || safe.Chain != chain || safe.State != common.RequestStateDone {
		return nil
	}

	sbm, err := node.keeperStore.ReadPositiveEthereumTokenBalancesMap(ctx, safe.Address)
	logger.Verbosef("keeperStore.ReadPositiveEthereumTokenBalancesMap(%s) => %d %v", safe.Address, len(sbm), err)
	if err != nil || len(sbm) >= ethereum.MaxAssetsCount/2 {
		return err
	}

	asset, err := node.fetchMixinAsset(ctx, transfer.AssetId)
	logger.Printf("node.fetchMixinAsset(%s, %s) => %v %v", transfer.Hash, transfer.AssetId, asset, err)
	if err != nil || asset == nil {
		return err
	}
	if !checkGoodAsset(asset) {
		return nil
	}

	amount, err := node.ethereumDepositAmount(transfer, chain)
	if err != nil {
		return nil
	}
	if amount.Cmp(minimum) < 0 {
		return nil
	}
	priceUSD := decimal.RequireFromString(asset.PriceUSD)
	if amount.Mul(priceUSD).Cmp(minimumEthereumDepositValueUSD) < 0 {
		return nil
	}

	createdAt := time.Now().UTC()
	deposit := &PendingDeposit{
		TransactionHash: transfer.Hash,
		OutputIndex:     transfer.Index,
		AssetId:         transfer.AssetId,
		AssetAddress:    transfer.TokenAddress,
		Amount:          amount.String(),
		Receiver:        transfer.Receiver,
		Sender:          transfer.Sender,
		State:           common.RequestStateInitial,
		Chain:           chain,
		Holder:          safe.Holder,
		CreatedAt:       createdAt,
	}

	err = node.store.WritePendingDepositRecord(ctx, deposit)
	if err != nil {
		return fmt.Errorf("store.WritePendingDepositRecord(%v) => %v", deposit, err)
	}
	return nil
}
