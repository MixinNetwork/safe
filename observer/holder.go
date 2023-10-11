package observer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/btcsuite/btcd/wire"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid/v5"
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

func (node *Node) keeperSaveAccountProposal(ctx context.Context, chain byte, extra []byte, createdAt time.Time) error {
	logger.Printf("node.keeperSaveAccountProposal(%d, %x, %s)", chain, extra, createdAt)
	var sp *store.SafeProposal
	switch chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		wsa, err := bitcoin.UnmarshalWitnessScriptAccount(extra)
		if err != nil {
			return err
		}
		sp, err = node.keeperStore.ReadSafeProposalByAddress(ctx, wsa.Address)
		if err != nil {
			return err
		}
	case keeper.SafeChainEthereum, keeper.SafeChainMVM:
		gs, err := ethereum.UnmarshalGnosisSafe(extra)
		if err != nil {
			return err
		}
		sp, err = node.keeperStore.ReadSafeProposalByAddress(ctx, gs.Address)
		if err != nil {
			return err
		}
	}
	if sp.Chain != chain {
		return fmt.Errorf("inconsistent chain between SafeProposal and keeper response: %d, %d", sp.Chain, chain)
	}

	var assetId string
	switch sp.Chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		_, assetId = node.bitcoinParams(sp.Chain)
	case keeper.SafeChainEthereum, keeper.SafeChainMVM:
		_, assetId = node.ethereumParams(sp.Chain)
	}
	_, err := node.checkOrDeployKeeperBond(ctx, assetId, sp.Holder)
	logger.Printf("node.checkOrDeployKeeperBond(%s, %s) => %v", assetId, sp.Holder, err)
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

func (node *Node) httpCreateBitcoinAccountRecoveryRequest(ctx context.Context, addr, raw, hash string) error {
	logger.Printf("node.httpCreateBitcoinAccountRecoveryRequest(%s, %s, %s)", addr, raw, hash)
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

	if hash == "" || raw == "" {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
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

	switch {
	case approval != nil: // Close account with safeBTC
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
	case approval == nil: // Close account with holder key
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

func (node *Node) httpSignBitcoinAccountRecoveryRequest(ctx context.Context, addr, raw, hash string) error {
	logger.Printf("node.httpSignBitcoinAccountRecoveryRequest(%s, %s, %s)", addr, raw, hash)
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

	r, err := node.store.ReadRecovery(ctx, safe.Address)
	if err != nil {
		return err
	}
	if r == nil || r.State != common.RequestStateInitial {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	if r.TransactionHash != hash {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

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

	var extra []byte
	id := mixin.UniqueConversationID(safe.Address, receiver)
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
		extra = uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	case isHolderSigned: // Close account with holder key
		if !bitcoin.CheckTransactionPartiallySignedBy(raw, safe.Holder) {
			return fmt.Errorf("bitcoin.CheckTransactionPartiallySignedBy(%s, %s) holder", raw, safe.Holder)
		}
		extra = uuid.Nil.Bytes()
		id = uuid.FromBytesOrNil(msgTx.TxOut[1].PkScript[2:]).String()
	}

	objectRaw := signedRaw
	rawId := mixin.UniqueConversationID(raw, raw)
	objectRaw = append(uuid.Must(uuid.FromString(rawId)).Bytes(), objectRaw...)
	objectRaw = common.AESEncrypt(node.aesKey[:], objectRaw, rawId)
	msg := base64.RawURLEncoding.EncodeToString(objectRaw)
	traceId := mixin.UniqueConversationID(msg, msg)
	conf := node.conf.App
	rs, err := common.CreateObjectUntilSufficient(ctx, msg, traceId, conf.ClientId, conf.SessionId, conf.PrivateKey, conf.PIN, conf.PinToken)
	logger.Printf("common.CreateObjectUntilSufficient(%v) => %v %v", msg, rs, err)
	if err != nil {
		return err
	}
	ref, err := crypto.HashFromString(rs.TransactionHash)
	if err != nil {
		return err
	}

	extra = append(extra, ref[:]...)
	action := common.ActionBitcoinSafeCloseAccount
	references := []crypto.Hash{ref}
	err = node.sendBitcoinKeeperResponseWithReferences(ctx, safe.Holder, byte(action), safe.Chain, id, extra, references)
	logger.Printf("node.sendBitcoinKeeperResponseWithReferences(%s, %s, %x, %v) => %v", safe.Holder, id, extra, references, err)
	if err != nil {
		return err
	}

	if isHolderSigned {
		err = node.store.FinishTransactionSignatures(ctx, hash, hex.EncodeToString(signedRaw))
		logger.Printf("store.FinishTransactionSignatures(%s, %x) => %v", hash, signedRaw, err)
		if err != nil {
			return err
		}
		return node.store.UpdateRecoveryState(ctx, addr, raw, common.RequestStateDone)
	}

	err = node.store.AddTransactionPartials(ctx, hash, hex.EncodeToString(signedRaw))
	logger.Printf("store.AddTransactionPartials(%s) => %v", hash, err)
	return node.store.UpdateRecoveryState(ctx, addr, raw, common.RequestStatePending)
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

	id := mixin.UniqueConversationID(approval.TransactionHash, approval.TransactionHash)
	rid := uuid.Must(uuid.FromString(tx.RequestId))
	extra := append(rid.Bytes(), sig...)
	action := common.ActionBitcoinSafeRevokeTransaction
	err = node.sendBitcoinKeeperResponse(ctx, tx.Holder, byte(action), approval.Chain, id, extra)
	logger.Printf("node.sendBitcoinKeeperResponse(%s, %d, %s, %x)", tx.Holder, action, id, extra)
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
			logger.Verbosef("node.sendToKeeperBitcoinApproveTransaction(%v) => %v", approval, err)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) sendToKeeperBitcoinApproveTransaction(ctx context.Context, approval *Transaction) error {
	signed, err := node.bitcoinCheckKeeperSignedTransaction(ctx, approval)
	logger.Printf("node.bitcoinCheckKeeperSignedTransaction(%v) => %t %v", approval, signed, err)
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
	traceId := mixin.UniqueConversationID(msg, msg)
	conf := node.conf.App
	rs, err := common.CreateObjectUntilSufficient(ctx, msg, traceId, conf.ClientId, conf.SessionId, conf.PrivateKey, conf.PIN, conf.PinToken)
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
	logger.Printf("node.sendBitcoinKeeperResponseWithReferences(%s, %d, %s, %x, %s)", tx.Holder, action, id, extra, ref)
	if err != nil {
		return err
	}

	if approval.UpdatedAt.Add(keeper.SafeSignatureTimeout).After(time.Now()) {
		return nil
	}
	id = mixin.UniqueConversationID(id, approval.UpdatedAt.String())
	err = node.sendBitcoinKeeperResponseWithReferences(ctx, tx.Holder, byte(action), approval.Chain, id, extra, references)
	logger.Printf("node.sendBitcoinKeeperResponseWithReferences(%s, %d, %s, %x, %s)", tx.Holder, action, id, extra, ref)
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
