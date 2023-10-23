package observer

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	bitcoinKeygenRequestTimeKey  = "bitcoin-keygen-request-time"
	bitcoinKeyDummyHolderPrivate = "75d5f311c8647e3a1d84a0d975b6e50b8c6d3d7f195365320077f41c6a165155"
)

func bitcoinMixinSnapshotsCheckpointKey(chain byte) string {
	switch chain {
	case keeper.SafeChainBitcoin:
	case keeper.SafeChainLitecoin:
	default:
		panic(chain)
	}
	return fmt.Sprintf("bitcoin-mixin-snapshots-checkpoint-%d", chain)
}

func bitcoinDepositCheckpointKey(chain byte) string {
	switch chain {
	case keeper.SafeChainBitcoin:
	case keeper.SafeChainLitecoin:
	default:
		panic(chain)
	}
	return fmt.Sprintf("bitcoin-deposit-checkpoint-%d", chain)
}

func bitcoinDepositCheckpointDefault(chain byte) int64 {
	switch chain {
	case keeper.SafeChainBitcoin:
		return 802220
	case keeper.SafeChainLitecoin:
		return 2523300
	default:
		panic(chain)
	}
}

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

func (node *Node) bitcoinNetworkInfoLoop(ctx context.Context, chain byte) {
	rpc, assetId := node.bitcoinParams(chain)

	for {
		time.Sleep(keeper.SafeNetworkInfoTimeout / 7)
		height, err := bitcoin.RPCGetBlockHeight(rpc)
		if err != nil {
			logger.Printf("bitcoin.RPCGetBlockHeight(%d) => %v", chain, err)
			continue
		}
		fvb, err := bitcoin.RPCEstimateSmartFee(chain, rpc)
		if err != nil {
			logger.Printf("bitcoin.RPCEstimateSmartFee(%d) => %v", chain, err)
			continue
		}
		blockHash, err := bitcoin.RPCGetBlockHash(rpc, height)
		if err != nil {
			logger.Printf("bitcoin.RPCGetBlockHash(%d, %d) => %v", chain, height, err)
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
		logger.Printf("node.bitcoinNetworkInfoLoop(%d) => %d %d %s %s", chain, height, fvb, blockHash, id)

		dummy := node.bitcoinDummyHolder()
		action := common.ActionObserverUpdateNetworkStatus
		err = node.sendKeeperResponse(ctx, dummy, byte(action), chain, id, extra)
		logger.Verbosef("node.sendKeeperResponse(%d, %s, %x) => %v", chain, id, extra, err)
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
		return bitcoin.RPCGetRawMempool(chain, rpc)
	}

	hash, err := bitcoin.RPCGetBlockHash(rpc, num)
	if err != nil {
		return nil, err
	}
	block, err := bitcoin.RPCGetBlockWithTransactions(chain, rpc, hash)
	if err != nil {
		return nil, err
	}
	return block.Tx, nil
}

func (node *Node) bitcoinWriteFeeOutput(ctx context.Context, receiver string, tx *bitcoin.RPCTransaction, index int64, value float64, chain byte) error {
	amount := decimal.NewFromFloat(value)
	if bitcoin.ParseSatoshi(amount.String()) < bitcoin.ValueDust(chain) {
		return nil
	}
	old, err := node.store.ReadBitcoinUTXO(ctx, tx.TxId, index, chain)
	logger.Printf("store.ReadBitcoinUTXO(%s, %d) => %v %v", tx.TxId, index, old, err)
	if err != nil {
		return fmt.Errorf("store.ReadBitcoinUTXO(%s, %d) => %v", tx.TxId, index, err)
	} else if old != nil {
		return nil
	}

	accountant, err := node.store.ReadAccountantPrivateKey(ctx, receiver)
	logger.Printf("store.ReadAccountantPrivateKey(%s) => %v", receiver, err)
	if err != nil {
		return fmt.Errorf("store.ReadAccountantPrivateKey(%s) => %v", receiver, err)
	} else if accountant == "" {
		return nil
	}

	createdAt := time.Now().UTC()
	utxo := &Output{
		TransactionHash: tx.TxId,
		Index:           uint32(index),
		Address:         receiver,
		Satoshi:         bitcoin.ParseSatoshi(amount.String()),
		Chain:           chain,
		State:           common.RequestStateInitial,
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
	}

	err = node.store.WriteBitcoinUTXOIfNotExists(ctx, utxo)
	if err != nil {
		return fmt.Errorf("store.WriteBitcoinUTXOIfNotExists(%v) => %v", utxo, err)
	}
	return nil
}

func (node *Node) bitcoinCheckDepositChange(ctx context.Context, transactionHash string, outputIndex int64, sentHash string) bool {
	if sentHash == "" {
		return false
	}
	tx, err := node.keeperStore.ReadTransaction(ctx, sentHash)
	if err != nil || tx == nil {
		panic(fmt.Errorf("keeperStore.ReadTransaction(%s) => %v %v", transactionHash, tx, err))
	}
	var recipients []map[string]string
	err = json.Unmarshal([]byte(tx.Data), &recipients)
	if err != nil || len(recipients) == 0 {
		panic(fmt.Errorf("store.ReadTransaction(%s) => %s", transactionHash, tx.Data))
	}
	return outputIndex >= int64(len(recipients))
}

func (node *Node) bitcoinWritePendingDeposit(ctx context.Context, receiver string, tx *bitcoin.RPCTransaction, index int64, value float64, chain byte) error {
	_, assetId := node.bitcoinParams(chain)
	amount := decimal.NewFromFloat(value)
	minimum := decimal.RequireFromString(node.conf.TransactionMinimum)

	sent, err := node.store.QueryDepositSentHashes(ctx, []*Deposit{{TransactionHash: tx.TxId}})
	logger.Printf("store.QueryDepositSentHashes(%s) => %v %v", tx.TxId, sent, err)
	if err != nil {
		return fmt.Errorf("store.QueryDepositSentHashes(%s) => %v", tx.TxId, err)
	}
	change := node.bitcoinCheckDepositChange(ctx, tx.TxId, index, sent[tx.TxId])
	if amount.Cmp(minimum) < 0 && !change {
		return nil
	}

	old, _, err := node.keeperStore.ReadBitcoinUTXO(ctx, tx.TxId, int(index))
	logger.Printf("keeperStore.ReadBitcoinUTXO(%s, %d) => %v %v", tx.TxId, index, old, err)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadBitcoinUTXO(%s, %d) => %v", tx.TxId, index, err)
	} else if old != nil {
		return nil
	}

	safe, err := node.keeperStore.ReadSafeByAddress(ctx, receiver)
	logger.Printf("keeperStore.ReadSafeByAddress(%s) => %v %v", receiver, safe, err)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadSafeByAddress(%s) => %v", receiver, err)
	} else if safe == nil {
		return nil
	}

	createdAt := time.Now().UTC()
	deposit := &Deposit{
		TransactionHash: tx.TxId,
		OutputIndex:     index,
		AssetId:         assetId,
		Amount:          amount.String(),
		Receiver:        receiver,
		Holder:          safe.Holder,
		Category:        common.ActionObserverHolderDeposit,
		State:           common.RequestStateInitial,
		Chain:           chain,
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
	}

	rpc, _ := node.bitcoinParams(chain)
	sender, err := bitcoin.RPCGetTransactionSender(chain, rpc, tx)
	if err != nil {
		return fmt.Errorf("bitcoin.RPCGetTransactionSender(%s) => %v", tx.TxId, err)
	}
	deposit.Sender = sender

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
		checkpoint, err := node.bitcoinReadMixinSnapshotsCheckpoint(ctx, chain)
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
			logger.Printf("node.bitcoinProcessMixinSnapshot(%d, %v) => %v", chain, s, err)
			if err != nil {
				panic(err)
			}
		}
		if len(snapshots) < 100 {
			time.Sleep(time.Second)
		}

		err = node.bitcoinWriteMixinSnapshotsCheckpoint(ctx, checkpoint, chain)
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

	tx, err := bitcoin.RPCGetTransaction(chain, rpc, s.TransactionHash)
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
		checkpoint, err := node.bitcoinReadDepositCheckpoint(ctx, chain)
		if err != nil {
			panic(err)
		}
		height, err := bitcoin.RPCGetBlockHeight(rpc)
		if err != nil {
			logger.Printf("bitcoin.RPCGetBlockHeight(%d) => %v", chain, err)
			continue
		}
		logger.Printf("node.bitcoinReadDepositCheckpoint(%d) => %d %d", chain, checkpoint, height)
		if checkpoint > height {
			continue
		}
		txs, err := node.bitcoinReadBlock(ctx, checkpoint, chain)
		logger.Printf("node.bitcoinReadBlock(%d, %d) => %d %v", chain, checkpoint, len(txs), err)
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

		err = node.bitcoinWriteDepositCheckpoint(ctx, checkpoint+1, chain)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) bitcoinProcessTransaction(ctx context.Context, tx *bitcoin.RPCTransaction, chain byte) error {
	for index := range tx.Vout {
		out := tx.Vout[index]
		skt := out.ScriptPubKey.Type
		if skt != bitcoin.ScriptPubKeyTypeWitnessScriptHash && skt != bitcoin.ScriptPubKeyTypeWitnessKeyHash {
			continue
		}
		if out.N != int64(index) {
			panic(tx.TxId)
		}

		err := node.bitcoinWritePendingDeposit(ctx, out.ScriptPubKey.Address, tx, out.N, out.Value, chain)
		if err != nil {
			panic(err)
		}
		err = node.bitcoinWriteFeeOutput(ctx, out.ScriptPubKey.Address, tx, out.N, out.Value, chain)
		if err != nil {
			panic(err)
		}
	}

	return nil
}

func (node *Node) bitcoinReadDepositCheckpoint(ctx context.Context, chain byte) (int64, error) {
	min := bitcoinDepositCheckpointDefault(chain)
	ckt, err := node.store.ReadProperty(ctx, bitcoinDepositCheckpointKey(chain))
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

func (node *Node) bitcoinWriteDepositCheckpoint(ctx context.Context, num int64, chain byte) error {
	return node.store.WriteProperty(ctx, bitcoinDepositCheckpointKey(chain), fmt.Sprint(num))
}

func (node *Node) bitcoinReadMixinSnapshotsCheckpoint(ctx context.Context, chain byte) (time.Time, error) {
	ckt, err := node.store.ReadProperty(ctx, bitcoinMixinSnapshotsCheckpointKey(chain))
	if err != nil || ckt == "" {
		return time.Now(), err
	}
	return time.Parse(time.RFC3339Nano, ckt)
}

func (node *Node) bitcoinWriteMixinSnapshotsCheckpoint(ctx context.Context, offset time.Time, chain byte) error {
	return node.store.WriteProperty(ctx, bitcoinMixinSnapshotsCheckpointKey(chain), offset.Format(time.RFC3339Nano))
}
