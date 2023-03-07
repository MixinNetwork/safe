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
	bitcoinKeygenRequestTimeKey     = "bitcoin-keygen-request-time"
	bitcoinDepositCheckpointKey     = "bitcoin-deposit-checkpoint"
	bitcoinDepositCheckpointDefault = 779456
	bitcoinKeyDummyHolderPrivate    = "75d5f311c8647e3a1d84a0d975b6e50b8c6d3d7f195365320077f41c6a165155"
)

func (node *Node) bitcoinNetworkInfoLoop(ctx context.Context) {
	for {
		time.Sleep(keeper.SafeNetworkInfoTimeout / 7)
		height, err := bitcoin.RPCGetBlockHeight(node.conf.BitcoinRPC)
		if err != nil {
			logger.Printf("bitcoin.RPCGetBlockHeight() => %v", err)
			continue
		}
		fvb, err := bitcoin.RPCEstimateSmartFee(node.conf.BitcoinRPC)
		if err != nil {
			logger.Printf("bitcoin.RPCEstimateSmartFee() => %v", err)
			continue
		}
		blockHash, err := bitcoin.RPCGetBlockHash(node.conf.BitcoinRPC, height)
		if err != nil {
			logger.Printf("bitcoin.RPCGetBlockHash(%d) => %v", height, err)
			continue
		}
		hash, err := crypto.HashFromString(blockHash)
		if err != nil {
			panic(err)
		}
		extra := []byte{keeper.SafeChainBitcoin}
		extra = binary.BigEndian.AppendUint64(extra, uint64(fvb))
		extra = binary.BigEndian.AppendUint64(extra, uint64(height))
		extra = append(extra, hash[:]...)
		id := mixin.UniqueConversationID(keeper.SafeBitcoinChainId, fmt.Sprintf("%s:%d", blockHash, height))
		id = mixin.UniqueConversationID(id, fmt.Sprintf("%d:%d", time.Now().UnixNano(), fvb))
		logger.Printf("node.bitcoinNetworkInfoLoop() => %d %d %s %s", height, fvb, blockHash, id)

		dummy := node.bitcoinDummyHolder()
		action := common.ActionObserverUpdateNetworkStatus
		err = node.sendBitcoinKeeperResponse(ctx, dummy, byte(action), id, extra)
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

func (node *Node) bitcoinReadBlock(ctx context.Context, num int64) ([]*bitcoin.RPCTransaction, error) {
	if num == 0 {
		return bitcoin.RPCGetRawMempool(node.conf.BitcoinRPC)
	}

	hash, err := bitcoin.RPCGetBlockHash(node.conf.BitcoinRPC, num)
	if err != nil {
		return nil, err
	}
	block, err := bitcoin.RPCGetBlockWithTransactions(node.conf.BitcoinRPC, hash)
	if err != nil {
		return nil, err
	}
	return block.Tx, nil
}

func (node *Node) bitcoinWritePendingDeposit(ctx context.Context, receiver, txId string, index int64, value float64) error {
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
		AssetId:         keeper.SafeBitcoinChainId,
		Amount:          decimal.NewFromFloat(value).String(),
		Receiver:        receiver,
		State:           common.RequestStateInitial,
		Chain:           keeper.SafeChainBitcoin,
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
	bonded, err := node.checkOrDeployKeeperBond(ctx, keeper.SafeBitcoinChainId, deposit.Holder)
	if err != nil {
		return fmt.Errorf("node.checkOrDeployKeeperBond(%s) => %v", deposit.Holder, err)
	} else if !bonded {
		return nil
	}

	info, err := node.keeperStore.ReadNetworkInfo(ctx, keeper.SafeChainBitcoin)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadNetworkInfo(%d) => %v", keeper.SafeChainBitcoin, err)
	} else if info == nil {
		return nil
	}
	if info.CreatedAt.Add(keeper.SafeNetworkInfoTimeout / 7).Before(time.Now()) {
		return nil
	}
	if info.CreatedAt.After(time.Now()) {
		panic(fmt.Errorf("malicious bitcoin network info %v", info))
	}

	output, err := bitcoin.RPCGetTransactionOutput(node.conf.BitcoinRPC, deposit.TransactionHash, deposit.OutputIndex)
	if err != nil || output == nil {
		panic(fmt.Errorf("malicious bitcoin deposit or node not in sync? %s %v", deposit.TransactionHash, err))
	}
	if output.Address != deposit.Receiver || output.Satoshi != bitcoin.ParseSatoshi(deposit.Amount) {
		panic(fmt.Errorf("malicious bitcoin deposit %s", deposit.TransactionHash))
	}
	if info.Height < output.Height {
		return nil
	}
	confirmations := info.Height - output.Height + 1
	if !bitcoin.CheckFinalization(confirmations, output.Coinbase) {
		return nil
	}

	extra := deposit.encodeKeeperExtra()
	id := mixin.UniqueConversationID(keeper.SafeBitcoinChainId, deposit.Holder)
	id = mixin.UniqueConversationID(id, fmt.Sprintf("%s:%d", deposit.TransactionHash, deposit.OutputIndex))
	err = node.sendBitcoinKeeperResponse(ctx, deposit.Holder, deposit.Category, id, extra)
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

func (node *Node) bitcoinDepositConfirmLoop(ctx context.Context) {
	for {
		time.Sleep(3 * time.Second)
		deposits, err := node.store.ListPendingDeposits(ctx, keeper.SafeChainBitcoin)
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

func (node *Node) bitcoinRPCBlocksLoop(ctx context.Context) {
	for {
		time.Sleep(3 * time.Second)
		checkpoint, err := node.bitcoinReadDepositCheckpoint(ctx)
		if err != nil {
			panic(err)
		}
		height, err := bitcoin.RPCGetBlockHeight(node.conf.BitcoinRPC)
		if err != nil {
			logger.Printf("bitcoin.RPCGetBlockHeight() => %v", err)
			continue
		}
		logger.Printf("node.bitcoinReadDepositCheckpoint() => %d %d", checkpoint, height)
		if checkpoint > height {
			continue
		}
		txs, err := node.bitcoinReadBlock(ctx, checkpoint)
		logger.Printf("node.bitcoinReadBlock(%d) => %d %v", checkpoint, len(txs), err)
		if err != nil {
			continue
		}

		for _, tx := range txs {
			for index := range tx.Vout {
				out := tx.Vout[index]
				skt := out.ScriptPubKey.Type
				if skt != bitcoin.ScriptPubKeyTypeWitnessKeyHash && skt != bitcoin.ScriptPubKeyTypeWitnessScriptHash {
					continue
				}
				if out.N != int64(index) {
					panic(tx.TxId)
				}
				err := node.bitcoinWritePendingDeposit(ctx, out.ScriptPubKey.Address, tx.TxId, out.N, out.Value)
				if err != nil {
					panic(err)
				}
			}
		}

		err = node.bitcoinWriteDepositCheckpoint(ctx, checkpoint+1)
		if err != nil {
			panic(err)
		}
	}
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
