package observer

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/shopspring/decimal"
)

const (
	ethereumKeygenRequestTimeKey = "ethereum-keygen-request-time"
)

type Transfer struct {
	Index    int64
	Receiver string
	Value    *big.Int
}

func ethereumMixinSnapshotsCheckpointKey(chain byte) string {
	switch chain {
	case keeper.SafeChainMVM:
	default:
		panic(chain)
	}
	return fmt.Sprintf("ethereum-mixin-snapshots-checkpoint-%d", chain)
}

func ethereumDepositCheckpointKey(chain byte) string {
	switch chain {
	case keeper.SafeChainMVM:
	default:
		panic(chain)
	}
	return fmt.Sprintf("ethereum-deposit-checkpoint-%d", chain)
}

func ethereumDepositCheckpointDefault(chain byte) int64 {
	switch chain {
	case keeper.SafeChainMVM:
		return 43690750
	default:
		panic(chain)
	}
}

func (node *Node) ethereumParams(chain byte) (string, string) {
	switch chain {
	case keeper.SafeChainEthereum:
		return node.conf.EthereumRPC, keeper.SafeEthereumChainId
	case keeper.SafeChainMVM:
		return node.conf.MVMRPC, keeper.SafeMVMChainId
	default:
		panic(chain)
	}
}

func (node *Node) ethereumNetworkInfoLoop(ctx context.Context, chain byte) {
	rpc, assetId := node.ethereumParams(chain)

	for {
		time.Sleep(keeper.SafeNetworkInfoTimeout / 7)
		height, err := ethereum.RPCGetBlockHeight(rpc)
		if err != nil {
			logger.Printf("ethereum.RPCGetBlockHeight(%d) => %v", chain, err)
			continue
		}
		gasPrice, err := ethereum.RPCGetGasPrice(rpc)
		if err != nil {
			logger.Printf("ethereum.RPCEstimateSmartFee(%d) => %v", chain, err)
			continue
		}
		blockHash, err := ethereum.RPCGetBlockHash(rpc, height)
		if err != nil {
			logger.Printf("ethereum.RPCGetBlockHash(%d, %d) => %v", chain, height, err)
			continue
		}
		if strings.HasSuffix(blockHash, "0x") {
			blockHash = blockHash[2:]
		}
		hash, err := crypto.HashFromString(blockHash)
		if err != nil {
			panic(err)
		}
		extra := []byte{chain}
		extra = binary.BigEndian.AppendUint64(extra, gasPrice.Uint64())
		extra = binary.BigEndian.AppendUint64(extra, uint64(height))
		extra = append(extra, hash[:]...)
		id := mixin.UniqueConversationID(assetId, fmt.Sprintf("%s:%d", blockHash, height))
		id = mixin.UniqueConversationID(id, fmt.Sprintf("%d:%d", time.Now().UnixNano(), gasPrice.Uint64()))
		logger.Printf("node.ethereumNetworkInfoLoop(%d) => %d %d %s %s", chain, height, gasPrice.Uint64(), blockHash, id)

		dummy := node.bitcoinDummyHolder()
		action := common.ActionObserverUpdateNetworkStatus
		err = node.sendKeeperResponse(ctx, dummy, byte(action), chain, id, extra)
		logger.Verbosef("node.sendKeeperResponse(%d, %s, %x) => %v", chain, id, extra, err)
	}
}

func (node *Node) ethereumReadBlock(ctx context.Context, num int64, chain byte) ([]*ethereum.RPCTransaction, error) {
	rpc, _ := node.ethereumParams(chain)

	hash, err := ethereum.RPCGetBlockHash(rpc, num)
	if err != nil {
		return nil, err
	}
	block, err := ethereum.RPCGetBlockWithTransactions(rpc, hash)
	if err != nil {
		return nil, err
	}
	return block.Tx, nil
}

func (node *Node) ethereumWritePendingDeposit(ctx context.Context, transfer *Transfer, tx *ethereum.RPCTransaction, chain byte) error {
	_, assetId := node.ethereumParams(chain)
	amount := decimal.NewFromBigInt(transfer.Value, -ethereum.ValuePrecision)

	sent, err := node.store.QueryDepositSentHashes(ctx, []*Deposit{{TransactionHash: tx.Hash}})
	logger.Printf("store.QueryDepositSentHashes(%s) => %v %v", tx.Hash, sent, err)
	if err != nil {
		return fmt.Errorf("store.QueryDepositSentHashes(%s) => %v", tx.Hash, err)
	}
	if sent[tx.Hash] != "" {
		return nil
	}

	old, err := node.keeperStore.ReadDeposit(ctx, tx.Hash, transfer.Index, assetId, transfer.Receiver)
	logger.Printf("keeperStore.ReadDeposit(%s, %d, %s, %s) => %v %v", tx.Hash, transfer.Index, assetId, transfer.Receiver, old, err)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadDeposit(%s, %d, %s, %s) => %v %v", tx.Hash, transfer.Index, assetId, transfer.Receiver, old, err)
	} else if old != nil {
		return nil
	}

	safe, err := node.keeperStore.ReadSafeByAddress(ctx, transfer.Receiver)
	logger.Printf("keeperStore.ReadSafeByAddress(%s) => %v %v", transfer.Receiver, safe, err)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadSafeByAddress(%s) => %v", transfer.Receiver, err)
	} else if safe == nil {
		return nil
	}

	createdAt := time.Now().UTC()
	deposit := &Deposit{
		TransactionHash: tx.Hash,
		OutputIndex:     transfer.Index,
		AssetId:         assetId,
		Amount:          amount.String(),
		Receiver:        transfer.Receiver,
		Sender:          tx.From,
		Holder:          safe.Holder,
		Category:        common.ActionObserverHolderDeposit,
		State:           common.RequestStateInitial,
		Chain:           chain,
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
	}

	err = node.store.WritePendingDepositIfNotExists(ctx, deposit)
	if err != nil {
		return fmt.Errorf("store.WritePendingDeposit(%v) => %v", deposit, err)
	}
	return nil
}

func (node *Node) ethereumConfirmPendingDeposit(ctx context.Context, deposit *Deposit) error {
	rpc, assetId := node.ethereumParams(deposit.Chain)

	bonded, err := node.checkOrDeployKeeperBond(ctx, assetId, deposit.Holder)
	if err != nil {
		return fmt.Errorf("node.checkOrDeployKeeperBond(%s) => %v", deposit.Holder, err)
	} else if !bonded {
		return nil
	}

	info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, deposit.Chain, time.Now())
	if err != nil {
		return fmt.Errorf("keeperStore.ReadLatestNetworkInfo(%d) => %v", deposit.Chain, err)
	} else if info == nil {
		return nil
	}
	if info.CreatedAt.Add(keeper.SafeNetworkInfoTimeout / 7).Before(time.Now()) {
		return nil
	}
	if info.CreatedAt.After(time.Now()) {
		panic(fmt.Errorf("malicious ethereum network info %v", info))
	}

	tx, err := ethereum.RPCGetTransactionByHash(rpc, deposit.TransactionHash)
	if err != nil || tx == nil {
		panic(fmt.Errorf("malicious ethereum deposit or node not in sync? %s %v", deposit.TransactionHash, err))
	}
	traces, err := ethereum.RPCDebugTraceTransactionByHash(rpc, deposit.TransactionHash)
	if err != nil {
		return err
	}
	transfers := loopCalls(traces, 0, 0)
	match := false
	for _, t := range transfers {
		if t.Receiver == deposit.Receiver && ethereum.ParseWei(deposit.Amount).Cmp(t.Value) == 0 {
			match = true
		}
	}
	if !match {
		panic(fmt.Errorf("malicious ethereum deposit %s", deposit.TransactionHash))
	}
	confirmations := info.Height - tx.BlockHeight + 1
	if info.Height < tx.BlockHeight {
		confirmations = 0
	}
	isDomain, err := common.CheckMixinDomainAddress(node.conf.MixinRPC, assetId, deposit.Sender)
	if err != nil {
		return fmt.Errorf("common.CheckMixinDomainAddress(%s) => %v", deposit.Sender, err)
	}
	if isDomain {
		confirmations = 1000000
	}
	isSafe, err := node.checkSafeInternalAddress(ctx, deposit.Sender)
	if err != nil {
		return fmt.Errorf("node.checkSafeInternalAddress(%s) => %v", deposit.Sender, err)
	}
	if isSafe {
		confirmations = 1000000
	}
	if confirmations < ethereum.TransactionConfirmations {
		return nil
	}

	extra := deposit.encodeKeeperExtra()
	id := mixin.UniqueConversationID(assetId, deposit.Holder)
	id = mixin.UniqueConversationID(id, fmt.Sprintf("%s:%d", deposit.TransactionHash, deposit.OutputIndex))
	err = node.sendKeeperResponse(ctx, deposit.Holder, deposit.Category, deposit.Chain, id, extra)
	if err != nil {
		return fmt.Errorf("node.sendKeeperResponse(%s) => %v", id, err)
	}
	err = node.store.ConfirmPendingDeposit(ctx, deposit.TransactionHash, deposit.OutputIndex)
	if err != nil {
		return fmt.Errorf("store.ConfirmPendingDeposit(%v) => %v", deposit, err)
	}
	return nil
}

func (node *Node) ethereumDepositConfirmLoop(ctx context.Context, chain byte) {
	for {
		time.Sleep(3 * time.Second)
		deposits, err := node.store.ListDeposits(ctx, int(chain), "", common.RequestStateInitial, 0)
		if err != nil {
			panic(err)
		}
		for _, d := range deposits {
			err := node.ethereumConfirmPendingDeposit(ctx, d)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) ethereumMixinWithdrawalsLoop(ctx context.Context, chain byte) {
	_, assetId := node.ethereumParams(chain)

	for {
		time.Sleep(time.Second)
		checkpoint, err := node.ethereumReadMixinSnapshotsCheckpoint(ctx, chain)
		if err != nil {
			panic(err)
		}
		snapshots, err := node.mixin.ReadNetworkSnapshots(ctx, assetId, checkpoint, "ASC", 100)
		if err != nil {
			continue
		}

		for _, s := range snapshots {
			checkpoint = s.CreatedAt
			if s.Source != "WITHDRAWAL_INITIALIZED" {
				continue
			}
			err = node.ethereumProcessMixinSnapshot(ctx, s.SnapshotID, chain)
			logger.Printf("node.ethereumProcessMixinSnapshot(%d, %v) => %v", chain, s, err)
			if err != nil {
				panic(err)
			}
		}
		if len(snapshots) < 100 {
			time.Sleep(time.Second)
		}

		err = node.ethereumWriteMixinSnapshotsCheckpoint(ctx, checkpoint, chain)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) ethereumProcessMixinSnapshot(ctx context.Context, id string, chain byte) error {
	rpc, _ := node.ethereumParams(chain)
	s, err := node.mixin.ReadNetworkSnapshot(ctx, id)
	if err != nil {
		time.Sleep(time.Second)
		logger.Printf("mixin.ReadNetworkSnapshot(%s) => %v", id, err)
		return node.ethereumProcessMixinSnapshot(ctx, id, chain)
	}
	if s.SnapshotHash == "" || s.TransactionHash == "" {
		time.Sleep(2 * time.Second)
		return node.ethereumProcessMixinSnapshot(ctx, id, chain)
	}

	tx, err := ethereum.RPCGetTransactionByHash(rpc, s.TransactionHash)
	if err != nil || tx == nil {
		time.Sleep(2 * time.Second)
		logger.Printf("ethereum.RPCGetTransactionByHash(%s, %s) => %v %v", id, s.TransactionHash, tx, err)
		return node.ethereumProcessMixinSnapshot(ctx, id, chain)
	}

	return node.ethereumProcessTransaction(ctx, tx, chain)
}

func (node *Node) ethereumRPCBlocksLoop(ctx context.Context, chain byte) {
	rpc, _ := node.ethereumParams(chain)

	for {
		time.Sleep(3 * time.Second)
		checkpoint, err := node.ethereumReadDepositCheckpoint(ctx, chain)
		if err != nil {
			panic(err)
		}
		height, err := ethereum.RPCGetBlockHeight(rpc)
		if err != nil {
			logger.Printf("ethereum.RPCGetBlockHeight(%d) => %v", chain, err)
			continue
		}
		logger.Printf("node.ethereumReadDepositCheckpoint(%d) => %d %d", chain, checkpoint, height)
		if checkpoint > height {
			continue
		}
		txs, err := node.ethereumReadBlock(ctx, checkpoint, chain)
		logger.Printf("node.ethereumReadBlock(%d, %d) => %d %v", chain, checkpoint, len(txs), err)
		if err != nil {
			continue
		}

		for _, tx := range txs {
			for {
				err := node.ethereumProcessTransaction(ctx, tx, chain)
				if err == nil {
					break
				}
				logger.Printf("node.ethereumProcessTransaction(%s) => %v", tx.Hash, err)
			}
		}

		err = node.ethereumWriteDepositCheckpoint(ctx, checkpoint+1, chain)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) ethereumReadMixinSnapshotsCheckpoint(ctx context.Context, chain byte) (time.Time, error) {
	ckt, err := node.store.ReadProperty(ctx, ethereumMixinSnapshotsCheckpointKey(chain))
	if err != nil || ckt == "" {
		return time.Now(), err
	}
	return time.Parse(time.RFC3339Nano, ckt)
}

func (node *Node) ethereumProcessTransaction(ctx context.Context, tx *ethereum.RPCTransaction, chain byte) error {
	rpc, _ := node.ethereumParams(chain)
	traces, err := ethereum.RPCDebugTraceTransactionByHash(rpc, tx.Hash)
	if err != nil {
		return err
	}
	transfers := loopCalls(traces, 0, 0)
	for _, transfer := range transfers {
		err := node.ethereumWritePendingDeposit(ctx, transfer, tx, chain)
		if err != nil {
			panic(err)
		}
	}
	return nil
}

func loopCalls(trace *ethereum.RPCTransactionCallTrace, layer, index int) []*Transfer {
	var transfers []*Transfer

	if trace.Value != "" && trace.Input == "0x" {
		value, _ := new(big.Int).SetString(trace.Value[2:], 16)
		if value.Cmp(big.NewInt(0)) > 0 {
			transfers = append(transfers, &Transfer{
				Index:    int64(layer*10 + index),
				Value:    value,
				Receiver: trace.To,
			})
		}
	}

	for i, c := range trace.Calls {
		ts := loopCalls(c, layer+1, i)
		for _, t := range ts {
			transfers = append(transfers, t)
		}
	}
	return transfers
}

func (node *Node) ethereumReadDepositCheckpoint(ctx context.Context, chain byte) (int64, error) {
	min := ethereumDepositCheckpointDefault(chain)
	ckt, err := node.store.ReadProperty(ctx, ethereumDepositCheckpointKey(chain))
	if err != nil || ckt == "" {
		return min, err
	}
	checkpoint, err := strconv.ParseInt(ckt, 10, 64)
	if err != nil {
		panic(ckt)
	}
	if checkpoint < min {
		checkpoint = min
	}
	return checkpoint, nil
}

func (node *Node) ethereumWriteDepositCheckpoint(ctx context.Context, num int64, chain byte) error {
	return node.store.WriteProperty(ctx, ethereumDepositCheckpointKey(chain), fmt.Sprint(num))
}

func (node *Node) ethereumWriteMixinSnapshotsCheckpoint(ctx context.Context, offset time.Time, chain byte) error {
	return node.store.WriteProperty(ctx, ethereumMixinSnapshotsCheckpointKey(chain), offset.Format(time.RFC3339Nano))
}
