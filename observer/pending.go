package observer

import (
	"context"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/shopspring/decimal"
)

func (node *Node) bitcoinPendingDepositsLoop(ctx context.Context, chain byte) {
	seen := make(map[string]bool)
	for {
		time.Sleep(5 * time.Second)
		err := node.scanBitcoinPendingDeposits(ctx, chain, seen)
		logger.Printf("node.scanBitcoinPendingDeposits(%d) => %v", chain, err)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) scanBitcoinPendingDeposits(ctx context.Context, chain byte, seen map[string]bool) error {
	rpc, _, _ := node.bitcoinParams(chain)
	hashes, err := bitcoin.RPCGetRawMempoolHashes(rpc)
	logger.Printf("bitcoin.RPCGetRawMempoolHashes(%d) => %d %v", chain, len(hashes), err)
	if err != nil {
		panic(err)
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
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) scanEthereumPendingDeposits(ctx context.Context, chain byte) error {
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
	_, transfers, err := node.ethereumReadBlockTransfers(ctx, height, chain)
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
