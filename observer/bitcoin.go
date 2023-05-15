package observer

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid"
	"github.com/shopspring/decimal"
)

const (
	bitcoinKeygenRequestTimeKey        = "bitcoin-keygen-request-time"
	bitcoinMixinSnapshotsCheckpointKey = "bitcoin-mixin-snapshots-checkpoint"
	bitcoinDepositCheckpointKey        = "bitcoin-deposit-checkpoint"
	bitcoinDepositCheckpointDefault    = 779456
	bitcoinKeyDummyHolderPrivate       = "75d5f311c8647e3a1d84a0d975b6e50b8c6d3d7f195365320077f41c6a165155"
)

func (node *Node) bitcoinParams(chain byte) (string, string) {
	switch chain {
	case keeper.SafeChainBitcoin:
		return node.conf.BitcoinRPC, keeper.SafeBitcoinChainId
	case keeper.SafeChainLitecoin:
		return node.conf.LitecoinRPC, keeper.SafeLitecoinChainId
	default:
		panic(chain)
	}
}

func (node *Node) bitcoinNetworkInfoLoop(ctx context.Context, chain byte) {
	rpc, assetId := node.bitcoinParams(chain)

	for {
		time.Sleep(keeper.SafeNetworkInfoTimeout / 7)
		height, err := bitcoin.RPCGetBlockHeight(rpc)
		if err != nil {
			logger.Printf("bitcoin.RPCGetBlockHeight() => %v", err)
			continue
		}
		fvb, err := bitcoin.RPCEstimateSmartFee(rpc)
		if err != nil {
			logger.Printf("bitcoin.RPCEstimateSmartFee() => %v", err)
			continue
		}
		blockHash, err := bitcoin.RPCGetBlockHash(rpc, height)
		if err != nil {
			logger.Printf("bitcoin.RPCGetBlockHash(%d) => %v", height, err)
			continue
		}
		hash, err := crypto.HashFromString(blockHash)
		if err != nil {
			panic(err)
		}
		extra := []byte{chain}
		extra = binary.BigEndian.AppendUint64(extra, uint64(fvb))
		extra = binary.BigEndian.AppendUint64(extra, uint64(height))
		extra = append(extra, hash[:]...)
		id := mixin.UniqueConversationID(assetId, fmt.Sprintf("%s:%d", blockHash, height))
		id = mixin.UniqueConversationID(id, fmt.Sprintf("%d:%d", time.Now().UnixNano(), fvb))
		logger.Printf("node.bitcoinNetworkInfoLoop() => %d %d %s %s", height, fvb, blockHash, id)

		dummy := node.bitcoinDummyHolder()
		action := common.ActionObserverUpdateNetworkStatus
		err = node.sendBitcoinKeeperResponse(ctx, dummy, byte(action), chain, id, extra)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) bitcoinDummyHolder() string {
	seed := common.DecodeHexOrPanic(bitcoinKeyDummyHolderPrivate)
	_, dk := btcec.PrivKeyFromBytes(seed)
	return hex.EncodeToString(dk.SerializeCompressed())
}

func (node *Node) bitcoinReadBlock(ctx context.Context, num int64, chain byte) ([]*bitcoin.RPCTransaction, error) {
	rpc, _ := node.bitcoinParams(chain)

	if num == 0 {
		return bitcoin.RPCGetRawMempool(rpc)
	}

	hash, err := bitcoin.RPCGetBlockHash(rpc, num)
	if err != nil {
		return nil, err
	}
	block, err := bitcoin.RPCGetBlockWithTransactions(rpc, hash)
	if err != nil {
		return nil, err
	}
	return block.Tx, nil
}

func (node *Node) bitcoinWritePendingDeposit(ctx context.Context, receiver, txId string, index int64, value float64, sender string, chain byte) error {
	_, assetId := node.bitcoinParams(chain)
	amount := decimal.NewFromFloat(value)
	minimum := decimal.RequireFromString(node.conf.TransactionMinimum)
	change, err := node.keeperStore.ReadTransaction(ctx, txId)
	logger.Printf("store.ReadTransaction(%s) => %v %v", txId, change, err)
	if err != nil {
		return fmt.Errorf("store.ReadTransaction(%s) => %v", txId, err)
	}
	if amount.Cmp(minimum) < 0 && change == nil {
		return nil
	}
	old, err := node.keeperStore.ReadBitcoinUTXO(ctx, txId, int(index))
	if err != nil {
		return fmt.Errorf("keeperStore.ReadBitcoinUTXO(%s, %d) => %v", txId, index, err)
	} else if old != nil {
		return nil
	}

	safe, err := node.keeperStore.ReadSafeByAddress(ctx, receiver)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadSafeByAddress(%s) => %v", receiver, err)
	}
	holder, err := node.keeperStore.ReadAccountantHolder(ctx, receiver)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadAccountantHolder(%s) => %v", receiver, err)
	}

	createdAt := time.Now().UTC()
	deposit := &Deposit{
		TransactionHash: txId,
		OutputIndex:     index,
		AssetId:         assetId,
		Amount:          amount.String(),
		Receiver:        receiver,
		Sender:          sender,
		State:           common.RequestStateInitial,
		Chain:           chain,
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
	}
	if safe != nil {
		deposit.Holder = safe.Holder
		deposit.Category = common.ActionObserverHolderDeposit
	} else if holder != "" {
		deposit.Holder = holder
		deposit.Category = common.ActionObserverAccountantDepost
	} else {
		return nil
	}

	err = node.store.WritePendingDepositIfNotExists(ctx, deposit)
	if err != nil {
		return fmt.Errorf("store.WritePendingDeposit(%v) => %v", deposit, err)
	}
	return nil
}

func (node *Node) bitcoinConfirmPendingDeposit(ctx context.Context, deposit *Deposit) error {
	rpc, assetId := node.bitcoinParams(deposit.Chain)

	bonded, err := node.checkOrDeployKeeperBond(ctx, assetId, deposit.Holder)
	if err != nil {
		return fmt.Errorf("node.checkOrDeployKeeperBond(%s) => %v", deposit.Holder, err)
	} else if !bonded {
		return nil
	}

	info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, deposit.Chain)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadLatestNetworkInfo(%d) => %v", deposit.Chain, err)
	} else if info == nil {
		return nil
	}
	if info.CreatedAt.Add(keeper.SafeNetworkInfoTimeout / 7).Before(time.Now()) {
		return nil
	}
	if info.CreatedAt.After(time.Now()) {
		panic(fmt.Errorf("malicious bitcoin network info %v", info))
	}

	_, output, err := bitcoin.RPCGetTransactionOutput(deposit.Chain, rpc, deposit.TransactionHash, deposit.OutputIndex)
	if err != nil || output == nil {
		panic(fmt.Errorf("malicious bitcoin deposit or node not in sync? %s %v", deposit.TransactionHash, err))
	}
	if output.Address != deposit.Receiver || output.Satoshi != bitcoin.ParseSatoshi(deposit.Amount) {
		panic(fmt.Errorf("malicious bitcoin deposit %s", deposit.TransactionHash))
	}
	confirmations := info.Height - output.Height + 1
	if info.Height < output.Height {
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
	if !bitcoin.CheckFinalization(confirmations, output.Coinbase) {
		return nil
	}

	extra := deposit.encodeKeeperExtra()
	id := mixin.UniqueConversationID(assetId, deposit.Holder)
	id = mixin.UniqueConversationID(id, fmt.Sprintf("%s:%d", deposit.TransactionHash, deposit.OutputIndex))
	err = node.sendBitcoinKeeperResponse(ctx, deposit.Holder, deposit.Category, deposit.Chain, id, extra)
	if err != nil {
		return fmt.Errorf("node.sendBitcoinKeeperResponse(%s) => %v", id, err)
	}
	err = node.store.ConfirmPendingDeposit(ctx, deposit.TransactionHash, deposit.OutputIndex)
	if err != nil {
		return fmt.Errorf("store.ConfirmPendingDeposit(%v) => %v", deposit, err)
	}
	return nil
}

func (deposit *Deposit) encodeKeeperExtra() []byte {
	hash, err := crypto.HashFromString(deposit.TransactionHash)
	if err != nil {
		panic(deposit.TransactionHash)
	}
	satoshi := bitcoin.ParseSatoshi(deposit.Amount)
	extra := []byte{deposit.Chain}
	extra = append(extra, uuid.Must(uuid.FromString(deposit.AssetId)).Bytes()...)
	extra = append(extra, hash[:]...)
	extra = binary.BigEndian.AppendUint64(extra, uint64(deposit.OutputIndex))
	extra = append(extra, big.NewInt(satoshi).Bytes()...)
	return extra
}

func (node *Node) bitcoinDepositConfirmLoop(ctx context.Context, chain byte) {
	for {
		time.Sleep(3 * time.Second)
		deposits, err := node.store.ListDeposits(ctx, int(chain), "", common.RequestStateInitial, 0)
		if err != nil {
			panic(err)
		}
		for _, d := range deposits {
			err := node.bitcoinConfirmPendingDeposit(ctx, d)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) bitcoinMixinWithdrawalsLoop(ctx context.Context, chain byte) {
	_, assetId := node.bitcoinParams(chain)

	for {
		time.Sleep(time.Second)
		checkpoint, err := node.bitcoinReadMixinSnapshotsCheckpoint(ctx)
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
			err = node.bitcoinProcessMixinSnapshot(ctx, s.SnapshotID, chain)
			if err != nil {
				panic(err)
			}
		}
		if len(snapshots) < 100 {
			time.Sleep(time.Second)
		}

		err = node.bitcoinWriteMixinSnapshotsCheckpoint(ctx, checkpoint)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) bitcoinProcessMixinSnapshot(ctx context.Context, id string, chain byte) error {
	rpc, _ := node.bitcoinParams(chain)
	s, err := node.mixin.ReadNetworkSnapshot(ctx, id)
	if err != nil {
		time.Sleep(time.Second)
		logger.Printf("mixin.ReadNetworkSnapshot(%s) => %v", id, err)
		return node.bitcoinProcessMixinSnapshot(ctx, id, chain)
	}
	if s.SnapshotHash == "" || s.TransactionHash == "" {
		time.Sleep(2 * time.Second)
		return node.bitcoinProcessMixinSnapshot(ctx, id, chain)
	}

	tx, err := bitcoin.RPCGetTransaction(rpc, s.TransactionHash)
	if err != nil || tx == nil {
		time.Sleep(2 * time.Second)
		logger.Printf("bitcoin.RPCGetTransaction(%s, %s) => %v %v", id, s.TransactionHash, tx, err)
		return node.bitcoinProcessMixinSnapshot(ctx, id, chain)
	}

	return node.bitcoinProcessTransaction(ctx, tx, chain)
}

func (node *Node) bitcoinRPCBlocksLoop(ctx context.Context, chain byte) {
	rpc, _ := node.bitcoinParams(chain)

	for {
		time.Sleep(3 * time.Second)
		checkpoint, err := node.bitcoinReadDepositCheckpoint(ctx)
		if err != nil {
			panic(err)
		}
		height, err := bitcoin.RPCGetBlockHeight(rpc)
		if err != nil {
			logger.Printf("bitcoin.RPCGetBlockHeight() => %v", err)
			continue
		}
		logger.Printf("node.bitcoinReadDepositCheckpoint() => %d %d", checkpoint, height)
		if checkpoint > height {
			continue
		}
		txs, err := node.bitcoinReadBlock(ctx, checkpoint, chain)
		logger.Printf("node.bitcoinReadBlock(%d) => %d %v", checkpoint, len(txs), err)
		if err != nil {
			continue
		}

		for _, tx := range txs {
			for {
				err := node.bitcoinProcessTransaction(ctx, tx, chain)
				if err == nil {
					break
				}
				logger.Printf("node.bitcoinProcessTransaction(%s) => %v", tx.TxId, err)
			}
		}

		err = node.bitcoinWriteDepositCheckpoint(ctx, checkpoint+1)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) bitcoinProcessTransaction(ctx context.Context, tx *bitcoin.RPCTransaction, chain byte) error {
	rpc, _ := node.bitcoinParams(chain)

	for index := range tx.Vout {
		out := tx.Vout[index]
		skt := out.ScriptPubKey.Type
		if skt != bitcoin.ScriptPubKeyTypeWitnessKeyHash && skt != bitcoin.ScriptPubKeyTypeWitnessScriptHash {
			continue
		}
		if out.N != int64(index) {
			panic(tx.TxId)
		}

		sender, err := bitcoin.RPCGetTransactionSender(rpc, tx)
		if err != nil {
			return fmt.Errorf("bitcoin.RPCGetTransactionSender(%s) => %v", tx.TxId, err)
		}
		err = node.bitcoinWritePendingDeposit(ctx, out.ScriptPubKey.Address, tx.TxId, out.N, out.Value, sender, chain)
		if err != nil {
			panic(err)
		}
	}

	return nil
}

func (node *Node) bitcoinReadDepositCheckpoint(ctx context.Context) (int64, error) {
	ckt, err := node.store.ReadProperty(ctx, bitcoinDepositCheckpointKey)
	if err != nil || ckt == "" {
		return bitcoinDepositCheckpointDefault, err
	}
	return strconv.ParseInt(ckt, 10, 64)
}

func (node *Node) bitcoinWriteDepositCheckpoint(ctx context.Context, num int64) error {
	return node.store.WriteProperty(ctx, bitcoinDepositCheckpointKey, fmt.Sprint(num))
}

func (node *Node) bitcoinReadMixinSnapshotsCheckpoint(ctx context.Context) (time.Time, error) {
	ckt, err := node.store.ReadProperty(ctx, bitcoinMixinSnapshotsCheckpointKey)
	if err != nil || ckt == "" {
		return time.Now(), err
	}
	return time.Parse(time.RFC3339Nano, ckt)
}

func (node *Node) bitcoinWriteMixinSnapshotsCheckpoint(ctx context.Context, offset time.Time) error {
	return node.store.WriteProperty(ctx, bitcoinMixinSnapshotsCheckpointKey, offset.Format(time.RFC3339Nano))
}
