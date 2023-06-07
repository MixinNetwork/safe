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

	err = node.store.RevokeTransactionApproval(ctx, txHash, sigBase64)
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
	utxo, _ := node.keeperStore.ReadBitcoinUTXO(ctx, pop.Hash.String(), int(pop.Index))
	return bitcoin.CheckMultisigHolderSignerScript(utxo.Script)
}
