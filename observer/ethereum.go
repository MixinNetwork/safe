package observer

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/fox-one/mixin-sdk-go"
)

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
	// todo
	return nil
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
