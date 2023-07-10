package observer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/MixinNetwork/bot-api-go-client"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/btcsuite/btcd/wire"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid"
)

func (node *Node) getSafeStatus(ctx context.Context, proposalId string) (string, error) {
	sp, err := node.keeperStore.ReadSafeProposal(ctx, proposalId)
	if err != nil || sp == nil {
		return "", err
	}
	safe, err := node.keeperStore.ReadSafeByAddress(ctx, sp.Address)
	if err != nil || safe == nil {
		return "proposed", err
	}
	if int(safe.State) == common.RequestStateFailed {
		return "failed", nil
	}
	return "approved", nil
}

func (node *Node) keeperSaveAccountProposal(ctx context.Context, extra []byte, createdAt time.Time) error {
	logger.Printf("node.keeperSaveAccountProposal(%x, %s)", extra, createdAt)
	wsa, err := bitcoin.UnmarshalWitnessScriptAccount(extra)
	if err != nil {
		return err
	}
	sp, err := node.keeperStore.ReadSafeProposalByAddress(ctx, wsa.Address)
	if err != nil {
		return err
	}
	return node.store.WriteAccountProposalIfNotExists(ctx, sp.Address, createdAt)
}

func (node *Node) keeperSaveTransactionProposal(ctx context.Context, extra []byte, createdAt time.Time) error {
	logger.Printf("node.keeperSaveTransactionProposal(%x, %s)", extra, createdAt)
	psbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(extra)
	txHash := psbt.UnsignedTx.TxHash().String()
	tx, err := node.keeperStore.ReadTransaction(ctx, txHash)
	if err != nil {
		return err
	}
	safe, err := node.keeperStore.ReadSafe(ctx, tx.Holder)
	if err != nil {
		return err
	}
	approval := &Transaction{
		TransactionHash: txHash,
		RawTransaction:  hex.EncodeToString(extra),
		Chain:           safe.Chain,
		Holder:          tx.Holder,
		Signer:          safe.Signer,
		State:           common.RequestStateInitial,
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
	}
	return node.store.WriteTransactionApprovalIfNotExists(ctx, approval)
}

func (node *Node) httpApproveBitcoinAccount(ctx context.Context, addr, sigBase64 string) error {
	logger.Printf("node.httpApproveBitcoinAccount(%s, %s)", addr, sigBase64)
	proposed, err := node.store.CheckAccountProposed(ctx, addr)
	if err != nil || !proposed {
		return err
	}
	sp, err := node.keeperStore.ReadSafeProposalByAddress(ctx, addr)
	if err != nil {
		return err
	}
	switch sp.Chain {
	case keeper.SafeChainBitcoin:
	case keeper.SafeChainLitecoin:
	default:
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigBase64)
	if err != nil {
		return err
	}
	ms := fmt.Sprintf("APPROVE:%s:%s", sp.RequestId, sp.Address)
	hash := bitcoin.HashMessageForSignature(ms, sp.Chain)
	err = bitcoin.VerifySignatureDER(sp.Holder, hash, sig)
	logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", sp, err)
	if err != nil {
		return err
	}

	id := mixin.UniqueConversationID(addr, sigBase64)
	rid := uuid.Must(uuid.FromString(sp.RequestId))
	extra := append(rid.Bytes(), sig...)
	action := common.ActionBitcoinSafeApproveAccount
	return node.sendBitcoinKeeperResponse(ctx, sp.Holder, byte(action), sp.Chain, id, extra)
}

func (node *Node) httpCloseBitcoinAccount(ctx context.Context, addr, raw, hash string) error {
	logger.Printf("node.httpCloseBitcoinAccount(%s, %s, %s)", addr, raw, hash)
	proposed, err := node.store.CheckAccountProposed(ctx, addr)
	if err != nil || !proposed {
		return err
	}
	sp, err := node.keeperStore.ReadSafeProposalByAddress(ctx, addr)
	if err != nil {
		return err
	}
	safe, err := node.keeperStore.ReadSafe(ctx, sp.Holder)
	if err != nil {
		return err
	}
	if safe == nil || safe.State != common.RequestStateDone {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	switch safe.Chain {
	case keeper.SafeChainBitcoin:
	case keeper.SafeChainLitecoin:
	default:
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	count, err := node.store.CountUnfinishedTransactionApprovalsForHolder(ctx, safe.Holder)
	if err != nil {
		return err
	}

	var rawTransaction string
	switch {
	case hash != "" && raw == "": // Close account with safeBTC
		if count != 1 {
			return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
		}

		approval, err := node.store.ReadTransactionApproval(ctx, hash)
		logger.Verbosef("store.ReadTransactionApproval(%s) => %v %v", hash, approval, err)
		if err != nil || approval == nil {
			return err
		}
		if approval.State != common.RequestStateInitial {
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
		rawTransaction = tx.RawTransaction
	case hash == "" && raw != "": // Close account with holder key
		if count != 0 {
			return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
		}

		rawTransaction = raw
	default:
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	rb := common.DecodeHexOrPanic(rawTransaction)
	psTx, err := bitcoin.UnmarshalPartiallySignedTransaction(rb)
	if err != nil {
		return err
	}
	msgTx := psTx.UnsignedTx

	rpc, _ := node.bitcoinParams(safe.Chain)
	info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, safe.Chain)
	logger.Printf("store.ReadLatestNetworkInfo(%d) => %v %v", safe.Chain, info, err)
	if err != nil {
		return err
	}
	if info == nil {
		return nil
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

	r := &Recovery{
		Address:         safe.Address,
		Chain:           safe.Chain,
		PublicKey:       safe.Holder,
		Observer:        safe.Observer,
		RawTransaction:  rawTransaction,
		TransactionHash: hash,
		State:           common.RequestStateInitial,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	err = node.store.WriteInitialRecovery(ctx, r)
	if err != nil {
		return err
	}

	err = node.keeperStore.CloseSafe(ctx, safe.Holder)
	return err
}

func (node *Node) httpRecoveryBitcoinAccount(ctx context.Context, addr, raw, hash string) error {
	logger.Printf("node.httpCloseBitcoinAccount(%s, %s, %s)", addr, raw, hash)
	proposed, err := node.store.CheckAccountProposed(ctx, addr)
	if err != nil || !proposed {
		return err
	}
	sp, err := node.keeperStore.ReadSafeProposalByAddress(ctx, addr)
	if err != nil {
		return err
	}
	safe, err := node.keeperStore.ReadSafe(ctx, sp.Holder)
	if err != nil {
		return err
	}
	if safe == nil || safe.State != common.RequestStateFailed {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	switch safe.Chain {
	case keeper.SafeChainBitcoin:
	case keeper.SafeChainLitecoin:
	default:
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	rb := common.DecodeHexOrPanic(raw)
	psTx, err := bitcoin.UnmarshalPartiallySignedTransaction(rb)
	if err != nil {
		return err
	}
	signedRaw := psTx.Marshal()
	msgTx := psTx.UnsignedTx

	rpc, _ := node.bitcoinParams(safe.Chain)
	info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, safe.Chain)
	logger.Printf("store.ReadLatestNetworkInfo(%d) => %v %v", safe.Chain, info, err)
	if err != nil {
		return err
	}
	if info == nil {
		return nil
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

	count, err := node.store.CountUnfinishedTransactionApprovalsForHolder(ctx, safe.Holder)
	if err != nil {
		return err
	}

	var extra []byte
	id := uuid.Must(uuid.NewV4()).String()
	switch {
	case hash != "": // Close account with safeBTC
		if count != 1 {
			return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
		}

		approval, err := node.store.ReadTransactionApproval(ctx, hash)
		logger.Verbosef("store.ReadTransactionApproval(%s) => %v %v", hash, approval, err)
		if err != nil || approval == nil {
			return err
		}
		if approval.State != common.RequestStateInitial {
			return nil
		}
		if bitcoin.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
			return nil
		}
		if !bitcoin.CheckTransactionPartiallySignedBy(raw, safe.Observer) {
			return nil
		}

		tx, err := node.keeperStore.ReadTransaction(ctx, hash)
		logger.Verbosef("keeperStore.ReadTransaction(%s) => %v %v", hash, tx, err)
		if err != nil || tx == nil {
			return err
		}
		extra = uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	case hash == "": // Close account with holder key
		if count != 0 {
			return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
		}

		if !bitcoin.CheckTransactionPartiallySignedBy(raw, safe.Holder) {
			return nil
		}
		if !bitcoin.CheckTransactionPartiallySignedBy(raw, safe.Observer) {
			return nil
		}

		extra = uuid.Nil.Bytes()
		id = uuid.FromBytesOrNil(msgTx.TxOut[1].PkScript[2:]).String()
	}

	rawId := mixin.UniqueConversationID(raw, raw)
	objectRaw := signedRaw
	objectRaw = append(uuid.Must(uuid.FromString(rawId)).Bytes(), objectRaw...)
	objectRaw = common.AESEncrypt(node.aesKey[:], objectRaw, rawId)
	msg := base64.RawURLEncoding.EncodeToString(objectRaw)
	fee := bot.EstimateObjectFee(msg)
	in := &bot.ObjectInput{
		TraceId: mixin.UniqueConversationID(msg, msg),
		Amount:  fee,
		Memo:    msg,
	}
	conf := node.conf.App
	rs, err := bot.CreateObject(ctx, in, conf.ClientId, conf.SessionId, conf.PrivateKey, conf.PIN, conf.PinToken)
	if err != nil {
		return err
	}
	ref, err := crypto.HashFromString(rs.TransactionHash)
	if err != nil {
		return err
	}

	extra = append(extra, ref[:]...)
	action := common.ActionBitcoinSafeCloseAccount
	err = node.sendBitcoinKeeperResponse(ctx, safe.Holder, byte(action), safe.Chain, id, extra)
	if err != nil {
		return err
	}

	err = node.store.MarkRecoveryPending(ctx, addr)
	return err
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
	tx, err := node.keeperStore.ReadTransaction(ctx, txHash)
	if err != nil || tx == nil {
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
	logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", tx, err)
	if err != nil {
		return err
	}

	id := mixin.UniqueConversationID(approval.TransactionHash, approval.TransactionHash)
	rid := uuid.Must(uuid.FromString(tx.RequestId))
	extra := append(rid.Bytes(), sig...)
	action := common.ActionBitcoinSafeRevokeTransaction
	err = node.sendBitcoinKeeperResponse(ctx, tx.Holder, byte(action), approval.Chain, id, extra)
	if err != nil {
		return err
	}

	err = node.store.RevokeTransactionApproval(ctx, txHash, sigBase64+":"+approval.RawTransaction)
	logger.Printf("store.RevokeTransactionApproval(%s) => %v", txHash, err)
	return err
}

func (node *Node) holderPayTransactionApproval(ctx context.Context, hash string) error {
	logger.Printf("node.holderPayTransactionApproval(%s)", hash)
	approval, err := node.store.ReadTransactionApproval(ctx, hash)
	logger.Printf("store.ReadTransactionApproval(%s) => %v %v", hash, approval, err)
	if err != nil || approval == nil {
		return err
	}
	if approval.State != common.RequestStateInitial {
		return nil
	}
	if !bitcoin.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
		return nil
	}
	return node.store.MarkTransactionApprovalPaid(ctx, hash)
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
			if err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) sendToKeeperBitcoinApproveTransaction(ctx context.Context, approval *Transaction) error {
	signed, err := node.bitcoinCheckKeeperSignedTransaction(ctx, approval)
	if err != nil || signed {
		return err
	}
	if !bitcoin.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
		panic(approval.RawTransaction)
	}

	rawId := mixin.UniqueConversationID(approval.RawTransaction, approval.RawTransaction)
	raw := common.DecodeHexOrPanic(approval.RawTransaction)
	raw = append(uuid.Must(uuid.FromString(rawId)).Bytes(), raw...)
	raw = common.AESEncrypt(node.aesKey[:], raw, rawId)
	msg := base64.RawURLEncoding.EncodeToString(raw)
	fee := bot.EstimateObjectFee(msg)
	in := &bot.ObjectInput{
		TraceId: mixin.UniqueConversationID(msg, msg),
		Amount:  fee,
		Memo:    msg,
	}
	conf := node.conf.App
	rs, err := bot.CreateObject(ctx, in, conf.ClientId, conf.SessionId, conf.PrivateKey, conf.PIN, conf.PinToken)
	if err != nil {
		return err
	}
	ref, err := crypto.HashFromString(rs.TransactionHash)
	if err != nil {
		return err
	}

	tx, err := node.keeperStore.ReadTransaction(ctx, approval.TransactionHash)
	if err != nil {
		return err
	}
	id := mixin.UniqueConversationID(approval.TransactionHash, approval.TransactionHash)
	rid := uuid.Must(uuid.FromString(tx.RequestId))
	extra := append(rid.Bytes(), ref[:]...)
	references := []crypto.Hash{ref}
	action := common.ActionBitcoinSafeApproveTransaction
	err = node.sendBitcoinKeeperResponseWithReferences(ctx, tx.Holder, byte(action), approval.Chain, id, extra, references)
	if err != nil {
		return err
	}

	if approval.UpdatedAt.Add(keeper.SafeSignatureTimeout * 2).After(time.Now()) {
		return nil
	}
	id = mixin.UniqueConversationID(id, approval.UpdatedAt.String())
	err = node.sendBitcoinKeeperResponseWithReferences(ctx, tx.Holder, byte(action), approval.Chain, id, extra, references)
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
