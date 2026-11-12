package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/shopspring/decimal"
)

type cachedPendingDeposit struct {
	Holder string          `json:"holder"`
	View   json.RawMessage `json:"view"`
}

// The cache belongs to one chain's refresh goroutine. Nil entries mark inspected
// transactions without safe outputs, so their full bodies need not be retained.
type pendingBitcoinMempool struct {
	transactions map[string]*bitcoin.RPCTransaction
	safes        map[string]*store.Safe
}

func (node *Node) pendingDepositsLoop(ctx context.Context, chain byte) {
	mempool := new(pendingBitcoinMempool)
	interval := 5 * time.Second
	switch chain {
	case common.SafeChainBitcoin, common.SafeChainLitecoin:
		interval = 30 * time.Second
	case common.SafeChainPolygon:
		interval = 2 * time.Second
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := node.cachePendingDeposits(ctx, chain, mempool); err != nil {
			logger.Printf("node.cachePendingDeposits(%d) => %v", chain, err)
		}
		timer.Reset(interval)
	}
}

func (node *Node) cachePendingDeposits(ctx context.Context, chain byte, mempool *pendingBitcoinMempool) (err error) {
	// RPC parsers may panic on inconsistent snapshots. A failed cache refresh
	// must not stop normal deposit processing.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("pending deposits for chain %d: %v", chain, r)
		}
	}()
	deposits, sent, err := node.listPendingDeposits(ctx, chain, "", mempool)
	if err != nil {
		return err
	}
	cached, err := node.readPendingDepositsCache(ctx, chain)
	if err != nil {
		return err
	}
	views := node.viewDeposits(ctx, deposits, sent)
	for i, d := range deposits {
		cached = append(cached, cachedPendingDeposit{Holder: d.Holder, View: common.MarshalJSONOrPanic(views[i])})
	}
	// A transfer can leave the latest block long before keeper processes it.
	// Retain the first discovery, including its timestamps, until keeper records it.
	type depositKey struct {
		Hash  string `json:"transaction_hash"`
		Index int64  `json:"output_index"`
	}
	seen := make(map[depositKey]bool)
	snapshot := make([]cachedPendingDeposit, 0, len(cached))
	for _, d := range cached {
		var key depositKey
		if err := json.Unmarshal(d.View, &key); err != nil {
			return err
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		confirmed, err := node.keeperStore.ReadDeposit(ctx, key.Hash, key.Index)
		if err != nil {
			return err
		} else if confirmed != nil {
			continue
		}
		snapshot = append(snapshot, d)
	}
	err = node.store.WriteCache(ctx, fmt.Sprintf("pending-deposits:%d", chain), string(common.MarshalJSONOrPanic(snapshot)))
	if err == nil {
		logger.Printf("node.cachePendingDeposits(%d) => %d deposits", chain, len(snapshot))
	}
	return err
}

func (node *Node) readPendingDepositsCache(ctx context.Context, chain byte) ([]cachedPendingDeposit, error) {
	value, err := node.store.ReadCache(ctx, fmt.Sprintf("pending-deposits:%d", chain), 0)
	if err != nil {
		return nil, err
	}
	var snapshot []cachedPendingDeposit
	if value != "" {
		if err := json.Unmarshal([]byte(value), &snapshot); err != nil {
			return nil, err
		}
	}
	return snapshot, nil
}

func (node *Node) readPendingDeposits(ctx context.Context, chain byte, holder string) ([]json.RawMessage, error) {
	snapshot, err := node.readPendingDepositsCache(ctx, chain)
	if err != nil {
		return nil, err
	}
	views := make([]json.RawMessage, 0, len(snapshot))
	for _, d := range snapshot {
		if holder == "" || d.Holder == holder {
			views = append(views, d.View)
		}
	}
	return views, nil
}

// listPendingDeposits returns a live snapshot, without writing deposits, caches,
// checkpoints or bonds. Normal deposit processing still verifies these transfers.
func (node *Node) listPendingDeposits(ctx context.Context, chain byte, holder string, mempool *pendingBitcoinMempool) ([]*Deposit, map[string]string, error) {
	ss, err := node.keeperStore.ListSafesWithState(ctx, common.RequestStateDone)
	if err != nil {
		return nil, nil, err
	}
	safes := make(map[string]*store.Safe)
	for _, s := range ss {
		if s.Chain == chain && (holder == "" || s.Holder == holder) {
			safes[s.Address] = s
		}
	}
	if len(safes) == 0 {
		return nil, nil, nil
	}

	var deposits []*Deposit
	var rpc string
	var params ChainParams
	bitcoinTransactions := make(map[string]*bitcoin.RPCTransaction)
	switch chain {
	case common.SafeChainBitcoin, common.SafeChainLitecoin:
		var assetID string
		rpc, assetID, params = node.bitcoinParams(chain)
		txs, err := readPendingBitcoinMempool(ctx, chain, rpc, safes, mempool)
		if err != nil {
			return nil, nil, err
		}
		height, err := bitcoin.RPCGetBlockHeight(ctx, rpc)
		if err != nil {
			return nil, nil, err
		}
		hash, err := bitcoin.RPCGetBlockHash(ctx, rpc, height)
		if err != nil {
			return nil, nil, err
		}
		block, err := bitcoin.RPCGetBlockWithTransactions(ctx, chain, rpc, hash)
		if err != nil {
			return nil, nil, err
		}
		for _, tx := range append(txs, block.Tx...) {
			if bitcoinTransactions[tx.TxId] != nil {
				continue
			}
			bitcoinTransactions[tx.TxId] = tx
			for index, out := range tx.Vout {
				if out == nil || out.ScriptPubKey == nil || out.N != int64(index) {
					return nil, nil, fmt.Errorf("invalid output %s:%d", tx.TxId, index)
				}
				script := out.ScriptPubKey
				if safes[script.Address] == nil || (script.Type != bitcoin.ScriptPubKeyTypeWitnessScriptHash && script.Type != bitcoin.ScriptPubKeyTypeWitnessKeyHash) {
					continue
				}
				deposits = append(deposits, &Deposit{
					TransactionHash: tx.TxId,
					OutputIndex:     out.N,
					AssetId:         assetID,
					Amount:          decimal.NewFromFloat(out.Value).String(),
					Receiver:        script.Address,
				})
			}
		}
	case common.SafeChainEthereum, common.SafeChainPolygon:
		var assetID string
		rpc, assetID, params = node.ethereumParams(chain)
		height, err := ethereum.RPCGetBlockHeight(ctx, rpc)
		if err != nil {
			return nil, nil, err
		}
		block, err := ethereum.RPCGetBlockWithTransactions(ctx, rpc, height)
		if err != nil {
			return nil, nil, err
		}
		traces, err := ethereum.RPCDebugTraceBlockByNumber(ctx, rpc, height)
		if err != nil {
			return nil, nil, err
		}
		transfers, err := ethereum.GetERC20TransferLogFromBlock(ctx, rpc, int64(chain), height)
		if err != nil {
			return nil, nil, err
		}
		transfers = append(ethereum.LoopBlockTraces(chain, assetID, traces, block), transfers...)
		decimals := map[string]int32{assetID: ethereum.ValuePrecision}
		for _, transfer := range transfers {
			if safes[transfer.Receiver] == nil {
				continue
			}
			precision, ok := decimals[transfer.AssetId]
			if !ok {
				asset, err := ethereum.FetchAsset(ctx, chain, rpc, transfer.TokenAddress)
				if err != nil {
					return nil, nil, err
				}
				precision = int32(asset.Decimals)
				decimals[transfer.AssetId] = precision
			}
			deposits = append(deposits, &Deposit{
				TransactionHash: transfer.Hash,
				OutputIndex:     transfer.Index,
				AssetId:         transfer.AssetId,
				AssetAddress:    transfer.TokenAddress,
				Amount:          decimal.NewFromBigInt(transfer.Value, -precision).RoundFloor(8).String(),
				Receiver:        transfer.Receiver,
				Sender:          transfer.Sender,
			})
		}
	}

	sent, err := node.store.QueryDepositSentHashes(ctx, deposits)
	if err != nil {
		return nil, nil, err
	}
	minimum := decimal.RequireFromString(params.TransactionMinimum)
	now := time.Now().UTC()
	pending := make([]*Deposit, 0, len(deposits))
	senders := make(map[string]string)
	for _, d := range deposits {
		amount := decimal.RequireFromString(d.Amount)
		change := bitcoinTransactions[d.TransactionHash] != nil && node.bitcoinCheckDepositChange(ctx, d.TransactionHash, d.OutputIndex, sent[d.TransactionHash])
		if amount.Sign() <= 0 || (amount.Cmp(minimum) < 0 && !change) {
			continue
		}
		old, err := node.keeperStore.ReadDeposit(ctx, d.TransactionHash, d.OutputIndex)
		if err != nil {
			return nil, nil, err
		} else if old != nil {
			continue
		}
		if tx := bitcoinTransactions[d.TransactionHash]; tx != nil {
			sender, ok := senders[tx.TxId]
			if !ok {
				sender, err = bitcoin.RPCGetTransactionSender(ctx, chain, rpc, tx)
				if err != nil {
					return nil, nil, err
				}
				senders[tx.TxId] = sender
			}
			d.Sender = sender
		}
		d.Holder = safes[d.Receiver].Holder
		d.Chain = chain
		d.State = common.RequestStateInitial
		d.CreatedAt, d.UpdatedAt = now, now
		pending = append(pending, d)
	}
	return pending, sent, nil
}

func readPendingBitcoinMempool(ctx context.Context, chain byte, rpc string, safes map[string]*store.Safe, mempool *pendingBitcoinMempool) ([]*bitcoin.RPCTransaction, error) {
	// Publish the transactions found so far even if a large mempool takes several
	// refreshes to inspect. Each refresh prioritizes new arrivals and retries misses.
	scanCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ids, err := bitcoin.RPCGetMempoolTransactionIDs(scanCtx, rpc)
	if err != nil {
		return nil, err
	}
	if mempool == nil {
		mempool = new(pendingBitcoinMempool)
	}
	reset := len(mempool.safes) != len(safes)
	for address := range safes {
		if mempool.safes[address] == nil {
			reset = true
		}
	}
	if reset || mempool.transactions == nil {
		mempool.transactions = make(map[string]*bitcoin.RPCTransaction)
	}
	mempool.safes = safes
	current := make(map[string]bool, len(ids))
	var missing []string
	for _, id := range ids {
		current[id] = true
		if _, ok := mempool.transactions[id]; !ok {
			missing = append(missing, id)
		}
	}
	for id := range mempool.transactions {
		if !current[id] {
			delete(mempool.transactions, id)
		}
	}

	type result struct {
		id  string
		tx  *bitcoin.RPCTransaction
		err error
	}
	const workers = 32
	jobs := make(chan string)
	results := make(chan result, workers)
	var wg sync.WaitGroup
	for range min(workers, len(missing)) {
		wg.Go(func() {
			for id := range jobs {
				readCtx, readCancel := context.WithTimeout(scanCtx, 5*time.Second)
				tx, err := bitcoin.RPCGetTransactionOnce(readCtx, chain, rpc, id)
				readCancel()
				select {
				case results <- result{id: id, tx: tx, err: err}:
				case <-scanCtx.Done():
					return
				}
			}
		})
	}
	go func() {
		defer close(jobs)
		for _, id := range missing {
			select {
			case jobs <- id:
			case <-scanCtx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	var firstError error
	for r := range results {
		if r.err != nil {
			if firstError == nil {
				firstError = r.err
			}
			continue
		}
		mempool.transactions[r.id] = nil
		for _, out := range r.tx.Vout {
			if out != nil && out.ScriptPubKey != nil && safes[out.ScriptPubKey.Address] != nil {
				mempool.transactions[r.id] = r.tx
				break
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var transactions []*bitcoin.RPCTransaction
	for _, id := range ids {
		if tx := mempool.transactions[id]; tx != nil {
			transactions = append(transactions, tx)
		}
	}
	logger.Printf("readPendingBitcoinMempool(%d) => %d total, %d inspected, %d remaining, %d matching, first error %v", chain,
		len(ids), len(mempool.transactions), len(ids)-len(mempool.transactions), len(transactions), firstError)
	return transactions, nil
}
