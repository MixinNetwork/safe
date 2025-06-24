package observer

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	bitcoinKeygenRequestTimeKey  = "bitcoin-keygen-request-time"
	bitcoinKeyDummyHolderPrivate = "75d5f311c8647e3a1d84a0d975b6e50b8c6d3d7f195365320077f41c6a165155"
)

func (node *Node) bitcoinParams(chain byte) (string, string) {
	switch chain {
	case common.SafeChainBitcoin:
		return node.conf.BitcoinRPC, common.SafeBitcoinChainId
	case common.SafeChainLitecoin:
		return node.conf.LitecoinRPC, common.SafeLitecoinChainId
	default:
		panic(chain)
	}
}

func (node *Node) bitcoinNetworkInfoLoop(ctx context.Context, chain byte) {
	rpc, assetId := node.bitcoinParams(chain)

	for {
		time.Sleep(depositNetworkInfoDelay)
		height, err := bitcoin.RPCGetBlockHeight(rpc)
		logger.Printf("bitcoin.RPCGetBlockHeight(%d) => %d %v", chain, height, err)
		if err != nil {
			continue
		}
		delay := node.getChainFinalizationDelay(chain)
		if delay > height || delay < 1 {
			panic(delay)
		}
		height = height + 1 - delay
		info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, chain, time.Now())
		if err != nil {
			panic(err)
		}
		if info != nil && info.Height > uint64(height) {
			logger.Printf("node.keeperStore.ReadLatestNetworkInfo(%d) => %v %d", chain, info, height)
			continue
		}
		fvb, err := bitcoin.EstimateAvgFee(chain, rpc)
		logger.Printf("bitcoin.EstimateAvgFee(%d) => %d %v", chain, fvb, err)
		if err != nil {
			continue
		}
		blockHash, err := bitcoin.RPCGetBlockHash(rpc, height)
		logger.Printf("bitcoin.RPCGetBlockHash(%d, %d) => %s %v", chain, height, blockHash, err)
		if err != nil {
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
		id := common.UniqueId(assetId, fmt.Sprintf("%s:%d", blockHash, height))
		id = common.UniqueId(id, fmt.Sprintf("%d:%d", time.Now().UnixNano(), fvb))
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

func (node *Node) bitcoinReadBlock(_ context.Context, num int64, chain byte) ([]*bitcoin.RPCTransaction, error) {
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

	c, err := node.keeperStore.ReadUnspentUtxoCountForSafe(ctx, receiver)
	logger.Printf("keeperStore.ReadUnspentUtxoCountForSafe(%s) => %d %v", receiver, c, err)
	if err != nil || c >= bitcoin.MaxUnspentUtxo/2 {
		return err
	}

	id := common.UniqueId(assetId, safe.Holder)
	id = common.UniqueId(id, fmt.Sprintf("%s:%d", tx.TxId, index))
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
		RequestId:       id,
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
	safe, err := node.keeperStore.ReadSafe(ctx, deposit.Holder)
	logger.Printf("node.bitcoinConfirmPendingDeposit(%v) => %v %v", deposit, safe, err)
	if err != nil || safe == nil {
		return err
	}
	bonded, err := node.checkOrDeployKeeperBond(ctx, deposit.Chain, assetId, "", deposit.Holder, safe.Address)
	logger.Printf("node.checkOrDeployKeeperBond(%v) => %t %v", deposit, bonded, err)
	if err != nil {
		return fmt.Errorf("node.checkOrDeployKeeperBond(%s) => %v", deposit.Holder, err)
	} else if !bonded {
		return nil
	}

	info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, deposit.Chain, time.Now())
	logger.Printf("keeperStore.ReadLatestNetworkInfo(%v) => %v %v", deposit, info, err)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadLatestNetworkInfo(%d) => %v", deposit.Chain, err)
	} else if info == nil {
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
	if output.Height < 1 {
		return nil
	}
	confirmations := info.Height - output.Height + 1
	if info.Height < output.Height {
		confirmations = 0
	}
	isSafe, err := node.checkTrustedSender(ctx, deposit.Sender)
	if err != nil {
		return fmt.Errorf("node.checkTrustedSender(%s) => %v", deposit.Sender, err)
	}
	if isSafe && confirmations > 0 {
		confirmations = 1000000
	}
	if !bitcoin.CheckFinalization(confirmations, output.Coinbase) {
		return nil
	}

	return node.sendKeeperDepositTransaction(ctx, deposit, bitcoin.ValuePrecision)
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

func (node *Node) bitcoinRPCBlocksLoop(ctx context.Context, chain byte) {
	rpc, _ := node.bitcoinParams(chain)
	duration := 3 * time.Minute
	switch chain {
	case common.SafeChainLitecoin:
		duration = 1 * time.Minute
	case common.SafeChainBitcoin:
	}

	for {
		checkpoint, err := node.readDepositCheckpoint(ctx, chain)
		if err != nil {
			panic(err)
		}
		height, err := bitcoin.RPCGetBlockHeight(rpc)
		if err != nil {
			logger.Printf("bitcoin.RPCGetBlockHeight(%d) => %v", chain, err)
			time.Sleep(time.Second * 5)
			continue
		}
		logger.Printf("node.bitcoinReadDepositCheckpoint(%d) => %d %d", chain, checkpoint, height)
		delay := node.getChainFinalizationDelay(chain)
		if checkpoint+delay > height+1 {
			time.Sleep(duration)
			continue
		}
		batch := node.getChainBlockBatch(chain)

		var wg sync.WaitGroup
		for range batch {
			ckpt := checkpoint + 1
			if ckpt+delay > int64(height)+1 {
				break
			}
			wg.Add(1)
			checkpoint = ckpt
			go func(current int64) {
				defer wg.Done()
				err := node.processBitcoinRPCBlock(ctx, chain, current)
				logger.Printf("node.processBitcoinRPCBlock(%d %d) => %v", chain, current, err)
				if err != nil {
					panic(err)
				}
			}(ckpt)
		}
		wg.Wait()

		err = node.store.writeBlockCheckpoint(ctx, chain, checkpoint)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) processBitcoinRPCBlock(ctx context.Context, chain byte, checkpoint int64) error {
	key := fmt.Sprintf("block:%d:%d", chain, checkpoint)
	val, err := node.store.ReadCache(ctx, key)
	if err != nil || val != "" {
		return err
	}

	txs, err := node.bitcoinReadBlock(ctx, checkpoint, chain)
	logger.Printf("node.bitcoinReadBlock(%d, %d) => %d %v", chain, checkpoint, len(txs), err)
	if err != nil {
		return err
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

	return node.store.WriteCache(ctx, key, "processed")
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

func (node *Node) bitcoinTransactionApprovalLoop(ctx context.Context, chain byte) {
	for {
		time.Sleep(3 * time.Second)
		approvals, err := node.store.ListPendingTransactionApprovals(ctx, chain)
		if err != nil {
			panic(err)
		}
		for _, approval := range approvals {
			err := node.sendToKeeperBitcoinApproveTransaction(ctx, approval)
			logger.Printf("node.sendToKeeperBitcoinApproveTransaction(%v) => %v", approval, err)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) sendToKeeperBitcoinApproveTransaction(ctx context.Context, approval *Transaction) error {
	safe, err := node.keeperStore.ReadSafe(ctx, approval.Holder)
	logger.Printf("store.ReadSafe(%s) => %v %v", approval.Holder, safe, err)
	if err != nil {
		return err
	}
	opk, err := node.deriveBIP32WithKeeperPath(ctx, safe.Observer, safe.Path)
	if err != nil {
		return err
	}
	if bitcoin.CheckTransactionPartiallySignedBy(approval.RawTransaction, opk) {
		return node.sendToKeeperBitcoinApproveRecoveryTransaction(ctx, approval)
	}
	return node.sendToKeeperBitcoinApproveNormalTransaction(ctx, approval)
}

func (node *Node) sendToKeeperBitcoinApproveNormalTransaction(ctx context.Context, approval *Transaction) error {
	signed, err := node.bitcoinCheckKeeperSignedTransaction(ctx, approval)
	logger.Printf("node.bitcoinCheckKeeperSignedTransaction(%v) => %t %v", approval, signed, err)
	if err != nil || signed {
		return err
	}
	if !bitcoin.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
		panic(approval.RawTransaction)
	}

	rawId := common.UniqueId(approval.RawTransaction, approval.RawTransaction)
	raw := common.DecodeHexOrPanic(approval.RawTransaction)
	raw = append(uuid.Must(uuid.FromString(rawId)).Bytes(), raw...)
	raw = common.AESEncrypt(node.aesKey[:], raw, rawId)
	msg := base64.RawURLEncoding.EncodeToString(raw)
	traceId := common.UniqueId(msg, msg)
	ref, err := common.CreateObjectStorageUntilSufficient(ctx, node.wallet, node.mixin, nil, raw, traceId, node.safeUser())
	if err != nil {
		return err
	}

	tx, err := node.keeperStore.ReadTransaction(ctx, approval.TransactionHash)
	if err != nil {
		return err
	}
	id := common.UniqueId(approval.TransactionHash, approval.TransactionHash)
	rid := uuid.Must(uuid.FromString(tx.RequestId))
	extra := append(rid.Bytes(), ref[:]...)
	references := []crypto.Hash{ref}
	action := common.ActionBitcoinSafeApproveTransaction
	err = node.sendKeeperResponseWithReferences(ctx, tx.Holder, byte(action), approval.Chain, id, extra, references)
	logger.Printf("node.sendKeeperResponseWithReferences(%s, %d, %s, %x, %s)", tx.Holder, action, id, extra, ref)
	if err != nil {
		return err
	}

	if approval.UpdatedAt.Add(keeper.SafeSignatureTimeout).After(time.Now()) {
		return nil
	}
	id = common.UniqueId(id, approval.UpdatedAt.String())
	err = node.sendKeeperResponseWithReferences(ctx, tx.Holder, byte(action), approval.Chain, id, extra, references)
	logger.Printf("node.sendKeeperResponseWithReferences(%s, %d, %s, %x, %s)", tx.Holder, action, id, extra, ref)
	if err != nil {
		return err
	}
	return node.store.UpdateTransactionApprovalRequestTime(ctx, approval.TransactionHash)
}

func (node *Node) sendToKeeperBitcoinApproveRecoveryTransaction(ctx context.Context, approval *Transaction) error {
	signedRaw := common.DecodeHexOrPanic(approval.RawTransaction)
	safe, err := node.keeperStore.ReadSafe(ctx, approval.Holder)
	logger.Printf("store.ReadSafe(%s) => %v %v", approval.Holder, safe, err)
	if err != nil {
		return err
	}
	psTx, err := bitcoin.UnmarshalPartiallySignedTransaction(signedRaw)
	if err != nil {
		return err
	}
	msgTx := psTx.UnsignedTx
	receiver, err := bitcoin.ExtractPkScriptAddr(msgTx.TxOut[0].PkScript, safe.Chain)
	logger.Printf("bitcoin.ExtractPkScriptAddr(%x) => %s %v", msgTx.TxOut[0].PkScript, receiver, err)
	if err != nil {
		return err
	}
	signedByHolder := bitcoin.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder)

	var extra []byte
	switch {
	case signedByHolder:
		extra = uuid.Nil.Bytes()
	default:
		signed, err := node.bitcoinCheckKeeperSignedTransaction(ctx, approval)
		logger.Printf("node.bitcoinCheckKeeperSignedTransaction(%v) => %t %v", approval, signed, err)
		if err != nil || signed {
			return err
		}
		tx, err := node.keeperStore.ReadTransaction(ctx, approval.TransactionHash)
		logger.Verbosef("keeperStore.ReadTransaction(%s) => %v %v", approval.TransactionHash, tx, err)
		if err != nil || tx == nil {
			return err
		}
		extra = uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	}

	objectRaw := signedRaw
	rawId := common.UniqueId(approval.RawTransaction, approval.RawTransaction)
	objectRaw = append(uuid.Must(uuid.FromString(rawId)).Bytes(), objectRaw...)
	objectRaw = common.AESEncrypt(node.aesKey[:], objectRaw, rawId)
	msg := base64.RawURLEncoding.EncodeToString(objectRaw)
	traceId := common.UniqueId(msg, msg)
	ref, err := common.CreateObjectStorageUntilSufficient(ctx, node.wallet, node.mixin, nil, objectRaw, traceId, node.safeUser())
	logger.Printf("common.CreateObjectStorageUntilSufficient(%v) => %s %v", msg, ref, err)
	if err != nil {
		return err
	}
	id := common.UniqueId(safe.Address, receiver)
	extra = append(extra, ref[:]...)
	action := common.ActionBitcoinSafeCloseAccount
	references := []crypto.Hash{ref}
	err = node.sendKeeperResponseWithReferences(ctx, safe.Holder, byte(action), safe.Chain, id, extra, references)
	logger.Printf("node.sendKeeperResponseWithReferences(%s, %s, %x, %v) => %v", safe.Holder, id, extra, references, err)
	if err != nil {
		return err
	}

	if approval.UpdatedAt.Add(keeper.SafeSignatureTimeout).After(time.Now()) {
		return nil
	}
	id = common.UniqueId(id, approval.UpdatedAt.String())
	err = node.sendKeeperResponseWithReferences(ctx, safe.Holder, byte(action), approval.Chain, id, extra, references)
	logger.Printf("node.sendKeeperResponseWithReferences(%s, %d, %s, %x, %s)", safe.Holder, action, id, extra, ref)
	if err != nil {
		return err
	}
	return node.store.UpdateTransactionApprovalRequestTime(ctx, approval.TransactionHash)
}

func (node *Node) bitcoinCheckKeeperSignedTransaction(ctx context.Context, approval *Transaction) (bool, error) {
	requests, err := node.keeperStore.ListAllSignaturesForTransaction(ctx, approval.TransactionHash, common.RequestStateDone)
	if err != nil {
		return false, err
	}
	signed := make(map[int][]byte)
	for _, r := range requests {
		signed[r.InputIndex] = common.DecodeHexOrPanic(r.Signature.String)
	}

	b := common.DecodeHexOrPanic(approval.RawTransaction)
	psbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)
	msgTx := psbt.UnsignedTx
	for idx := range msgTx.TxIn {
		pop := msgTx.TxIn[idx].PreviousOutPoint
		required := node.checkBitcoinUTXOSignatureRequired(ctx, pop)
		if required && len(signed[idx]) < 32 {
			return false, nil
		}
	}
	return true, nil
}

func (node *Node) checkBitcoinUTXOSignatureRequired(ctx context.Context, pop wire.OutPoint) bool {
	utxo, _, _ := node.keeperStore.ReadBitcoinUTXO(ctx, pop.Hash.String(), int(pop.Index))
	return bitcoin.CheckMultisigHolderSignerScript(utxo.Script)
}

func (node *Node) httpCreateBitcoinAccountRecoveryRequest(ctx context.Context, safe *store.Safe, raw, hash string) error {
	approval, err := node.store.ReadTransactionApproval(ctx, hash)
	logger.Verbosef("store.ReadTransactionApproval(%s) => %v %v", hash, approval, err)
	if err != nil {
		return err
	}
	count, err := node.store.CountUnfinishedTransactionApprovalsForHolder(ctx, safe.Holder)
	if err != nil {
		return err
	}

	rb := common.DecodeHexOrPanic(raw)
	psTx, err := bitcoin.UnmarshalPartiallySignedTransaction(rb)
	if err != nil {
		return err
	}
	msgTx := psTx.UnsignedTx
	txHash := psTx.Hash()
	if txHash != hash {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	isRecoveryTx := psTx.IsRecoveryTransaction()
	if !isRecoveryTx {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	if approval != nil {
		if count != 1 {
			return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
		}

		if approval.State != common.RequestStateInitial {
			return nil
		}
		if approval.TransactionHash != hash {
			return nil
		}
		if approval.RawTransaction != raw {
			return nil
		}
		if bitcoin.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
			return nil
		}

		tx, err := node.keeperStore.ReadTransaction(ctx, hash)
		logger.Verbosef("keeperStore.ReadTransaction(%s) => %v %v", hash, tx, err)
		if err != nil || tx == nil {
			return err
		}
	} else {
		if count != 0 {
			return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
		}

		if !bitcoin.CheckTransactionPartiallySignedBy(raw, safe.Holder) {
			return nil
		}
	}

	rpc, _ := node.bitcoinParams(safe.Chain)
	info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, safe.Chain, time.Now())
	logger.Printf("store.ReadLatestNetworkInfo(%d) => %v %v", safe.Chain, info, err)
	if err != nil || info == nil {
		return err
	}
	sequence := uint64(bitcoin.ParseSequence(safe.Timelock, safe.Chain))

	var balance int64
	for idx := range msgTx.TxIn {
		pop := msgTx.TxIn[idx].PreviousOutPoint
		_, bo, err := bitcoin.RPCGetTransactionOutput(safe.Chain, rpc, pop.Hash.String(), int64(pop.Index))
		logger.Printf("bitcoin.RPCGetTransactionOutput(%s, %d) => %v %v", pop.Hash.String(), pop.Index, bo, err)
		if err != nil {
			return err
		}
		if bo.Height > info.Height || bo.Height == 0 {
			return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
		}
		if bo.Height+sequence+100 > info.Height {
			return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
		}
		balance = balance + bo.Satoshi
	}
	if msgTx.TxOut[0].Value != balance {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	if len(msgTx.TxOut) != 2 || msgTx.TxOut[1].Value != 0 {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	receiver, err := bitcoin.ExtractPkScriptAddr(msgTx.TxOut[0].PkScript, safe.Chain)
	logger.Printf("bitcoin.ExtractPkScriptAddr(%x) => %s %v", msgTx.TxOut[0].PkScript, receiver, err)
	if err != nil {
		return err
	}
	if receiver == safe.Address {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	if approval == nil {
		approval = &Transaction{
			TransactionHash: hash,
			RawTransaction:  raw,
			Chain:           safe.Chain,
			Holder:          safe.Holder,
			Signer:          safe.Signer,
			State:           common.RequestStateInitial,
			CreatedAt:       time.Now().UTC(),
			UpdatedAt:       time.Now().UTC(),
		}
		err = node.store.WriteTransactionApprovalIfNotExists(ctx, approval)
		if err != nil {
			return err
		}
	}

	r := &Recovery{
		Address:         safe.Address,
		Chain:           safe.Chain,
		Holder:          safe.Holder,
		Observer:        safe.Observer,
		RawTransaction:  raw,
		TransactionHash: hash,
		State:           common.RequestStateInitial,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	return node.store.WriteInitialRecovery(ctx, r)
}

func (node *Node) httpSignBitcoinAccountRecoveryRequest(ctx context.Context, safe *store.Safe, raw, hash string) error {
	approval, err := node.store.ReadTransactionApproval(ctx, hash)
	logger.Verbosef("store.ReadTransactionApproval(%s) => %v %v", hash, approval, err)
	if err != nil || approval == nil {
		return err
	}
	if approval.TransactionHash != hash {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	if approval.State != common.RequestStateInitial {
		return nil
	}

	isHolderSigned := bitcoin.CheckTransactionPartiallySignedBy(approval.RawTransaction, safe.Holder)

	opk, err := node.deriveBIP32WithKeeperPath(ctx, safe.Observer, safe.Path)
	if err != nil {
		return err
	}
	if !bitcoin.CheckTransactionPartiallySignedBy(raw, opk) {
		return fmt.Errorf("bitcoin.CheckTransactionPartiallySignedBy(%s, %s) observer", raw, opk)
	}
	rb := common.DecodeHexOrPanic(raw)
	psTx, err := bitcoin.UnmarshalPartiallySignedTransaction(rb)
	if err != nil {
		return err
	}
	msgTx := psTx.UnsignedTx
	signedRaw := psTx.Marshal()
	txHash := psTx.Hash()
	if txHash != hash {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	isRecoveryTx := psTx.IsRecoveryTransaction()
	if !isRecoveryTx {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	rpc, _ := node.bitcoinParams(safe.Chain)

	var balance int64
	for idx := range msgTx.TxIn {
		pop := msgTx.TxIn[idx].PreviousOutPoint
		_, bo, err := bitcoin.RPCGetTransactionOutput(safe.Chain, rpc, pop.Hash.String(), int64(pop.Index))
		logger.Printf("bitcoin.RPCGetTransactionOutput(%s, %d) => %v %v", pop.Hash.String(), pop.Index, bo, err)
		if err != nil {
			return err
		}
		balance = balance + bo.Satoshi
	}
	if msgTx.TxOut[0].Value != balance {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	if len(msgTx.TxOut) != 2 || msgTx.TxOut[1].Value != 0 {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	receiver, err := bitcoin.ExtractPkScriptAddr(msgTx.TxOut[0].PkScript, safe.Chain)
	logger.Printf("bitcoin.ExtractPkScriptAddr(%x) => %s %v", msgTx.TxOut[0].PkScript, receiver, err)
	if err != nil {
		return err
	}
	if receiver == safe.Address {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	count, err := node.store.CountUnfinishedTransactionApprovalsForHolder(ctx, safe.Holder)
	logger.Printf("store.CountUnfinishedTransactionApprovalsForHolder(%s) => %d %v", safe.Holder, count, err)
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	switch {
	case !isHolderSigned: // Close account with safeBTC
		tx, err := node.keeperStore.ReadTransaction(ctx, hash)
		logger.Verbosef("keeperStore.ReadTransaction(%s) => %v %v", hash, tx, err)
		if err != nil {
			return err
		}
		if tx == nil {
			return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
		}
	case isHolderSigned: // Close account with holder key
		if !bitcoin.CheckTransactionPartiallySignedBy(raw, safe.Holder) {
			return fmt.Errorf("bitcoin.CheckTransactionPartiallySignedBy(%s, %s) holder", raw, safe.Holder)
		}
	}

	err = node.store.AddTransactionPartials(ctx, hash, hex.EncodeToString(signedRaw))
	logger.Printf("store.AddTransactionPartials(%s) => %v", hash, err)
	if err != nil {
		return err
	}
	return node.store.UpdateRecoveryState(ctx, safe.Address, raw, common.RequestStatePending)
}

func (node *Node) httpApproveBitcoinTransaction(ctx context.Context, raw string) error {
	logger.Printf("node.httpApproveBitcoinTransaction(%s)", raw)
	rb, _ := hex.DecodeString(raw)
	psbt, err := bitcoin.UnmarshalPartiallySignedTransaction(rb)
	if err != nil {
		return err
	}
	txHash := psbt.Hash()

	approval, err := node.store.ReadTransactionApproval(ctx, txHash)
	logger.Verbosef("store.ReadTransactionApproval(%s) => %v %v", txHash, approval, err)
	if err != nil || approval == nil {
		return err
	}
	if approval.State != common.RequestStateInitial {
		return nil
	}
	if bitcoin.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
		return nil
	}
	if !bitcoin.CheckTransactionPartiallySignedBy(raw, approval.Holder) {
		return nil
	}
	tx, err := node.keeperStore.ReadTransaction(ctx, txHash)
	logger.Verbosef("keeperStore.ReadTransaction(%s) => %v %v", txHash, tx, err)
	if err != nil || tx == nil {
		return err
	}

	raw = hex.EncodeToString(psbt.Marshal())
	err = node.store.AddTransactionPartials(ctx, txHash, raw)
	logger.Printf("store.AddTransactionPartials(%s) => %v", txHash, err)
	return err
}

func (node *Node) httpRevokeBitcoinTransaction(ctx context.Context, txHash string, sigBase64 string) error {
	logger.Printf("node.httpRevokeBitcoinTransaction(%s, %s)", txHash, sigBase64)
	approval, err := node.store.ReadTransactionApproval(ctx, txHash)
	logger.Verbosef("store.ReadTransactionApproval(%s) => %v %v", txHash, approval, err)
	if err != nil || approval == nil {
		return err
	}
	if approval.State != common.RequestStateInitial {
		return nil
	}
	if bitcoin.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
		return nil
	}

	tx, err := node.keeperStore.ReadTransaction(ctx, txHash)
	logger.Verbosef("keeperStore.ReadTransaction(%s) => %v %v", txHash, tx, err)
	if err != nil {
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigBase64)
	if err != nil {
		return err
	}
	ms := fmt.Sprintf("REVOKE:%s:%s", tx.RequestId, tx.TransactionHash)
	msg := bitcoin.HashMessageForSignature(ms, approval.Chain)
	err = bitcoin.VerifySignatureDER(tx.Holder, msg, sig)
	logger.Printf("holder: bitcoin.VerifySignatureDER(%v) => %v", tx, err)
	if err != nil {
		safe, err := node.keeperStore.ReadSafe(ctx, tx.Holder)
		if err != nil {
			return err
		}
		odk, err := node.deriveBIP32WithKeeperPath(ctx, safe.Observer, safe.Path)
		if err != nil {
			return err
		}
		err = bitcoin.VerifySignatureDER(odk, msg, sig)
		logger.Printf("observer: bitcoin.VerifySignatureDER(%v) => %v", tx, err)
		if err != nil {
			return err
		}
	}

	id := common.UniqueId(approval.TransactionHash, approval.TransactionHash)
	rid := uuid.Must(uuid.FromString(tx.RequestId))
	extra := append(rid.Bytes(), sig...)
	action := common.ActionBitcoinSafeRevokeTransaction
	err = node.sendKeeperResponse(ctx, tx.Holder, byte(action), approval.Chain, id, extra)
	logger.Printf("node.sendKeeperResponse(%s, %d, %s, %x)", tx.Holder, action, id, extra)
	if err != nil {
		return err
	}

	err = node.store.RevokeTransactionApproval(ctx, txHash, sigBase64+":"+approval.RawTransaction)
	logger.Printf("store.RevokeTransactionApproval(%s) => %v", txHash, err)
	return err
}
