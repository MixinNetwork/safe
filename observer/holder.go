package observer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

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

func (node *Node) saveAccountProposal(ctx context.Context, extra []byte, createdAt time.Time) error {
	wsa, _, err := bitcoin.UnmarshalWitnessScriptAccountWitAccountant(extra)
	if err != nil {
		return err
	}
	sp, err := node.keeperStore.ReadSafeProposalByAddress(ctx, wsa.Address)
	if err != nil {
		return err
	}
	return node.store.WriteAccountProposalIfNotExists(ctx, sp.Address, createdAt)
}

func (node *Node) saveTransactionProposal(ctx context.Context, extra []byte, createdAt time.Time) error {
	psbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(extra)
	txHash := psbt.MsgTx().TxHash().String()
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
		Accountant:      safe.Accountant,
		Partials:        map[int][]byte{},
		Signature:       "",
		State:           common.RequestStateInitial,
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
	}
	return node.store.WriteTransactionApprovalIfNotExists(ctx, approval)
}

func (node *Node) approveBitcoinAccount(ctx context.Context, addr, sigBase64 string) error {
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
	default:
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigBase64)
	if err != nil {
		return err
	}
	hash := bitcoin.HashMessageForSignature(sp.Address)
	err = bitcoin.VerifySignatureDER(sp.Holder, hash, sig)
	logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", sp, err)
	if err != nil {
		return err
	}

	id := mixin.UniqueConversationID(addr, sigBase64)
	rid := uuid.Must(uuid.FromString(sp.RequestId))
	extra := append(rid.Bytes(), sig...)
	action := common.ActionBitcoinSafeApproveAccount
	return node.sendBitcoinKeeperResponse(ctx, sp.Holder, byte(action), id, extra)
}

func (node *Node) approveBitcoinTransaction(ctx context.Context, raw string, holderSigs map[int][]byte, sigBase64 string) error {
	rb, err := hex.DecodeString(raw)
	if err != nil {
		return err
	}
	psbt, err := bitcoin.UnmarshalPartiallySignedTransaction(rb)
	if err != nil {
		return err
	}
	msgTx := psbt.MsgTx()
	txHash := msgTx.TxHash().String()

	approval, err := node.store.ReadTransactionApproval(ctx, txHash)
	if err != nil || approval == nil {
		return err
	}
	if approval.State != common.RequestStateInitial {
		return nil
	}
	if approval.RawTransaction != raw || len(approval.Partials) > 0 {
		return nil
	}

	tx, err := node.keeperStore.ReadTransaction(ctx, txHash)
	if err != nil {
		return err
	}

	for idx := range msgTx.TxIn {
		pop := msgTx.TxIn[idx].PreviousOutPoint
		required := node.checkBitcoinUTXOSignatureRequired(ctx, pop)
		if !required {
			continue
		}

		sig := holderSigs[idx]
		if sig == nil {
			return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
		}
		hash := psbt.SigHashes[idx*32 : idx*32+32]
		err = bitcoin.VerifySignatureDER(tx.Holder, hash, sig)
		if err != nil {
			return err
		}
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigBase64)
	if err != nil {
		return err
	}
	msg := bitcoin.HashMessageForSignature(txHash)
	err = bitcoin.VerifySignatureDER(tx.Holder, msg, sig)
	logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", tx, err)
	if err != nil {
		return err
	}

	err = node.store.AddTransactionPartials(ctx, txHash, holderSigs, sigBase64)
	logger.Printf("store.AddTransactionPartials(%s) => %v", txHash, err)
	return err
}

func (node *Node) bitcoinTransactionApprovalLoop(ctx context.Context) {
	for {
		time.Sleep(3 * time.Second)
		approvals, err := node.store.ListPendingTransactionApprovals(ctx, keeper.SafeChainBitcoin)
		if err != nil {
			panic(err)
		}
		for _, approval := range approvals {
			err := node.bitcoinApproveTransaction(ctx, approval)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) bitcoinApproveTransaction(ctx context.Context, approval *Transaction) error {
	btx, err := bitcoin.RPCGetTransaction(node.conf.BitcoinRPC, approval.TransactionHash)
	logger.Printf("bitcoin.RPCGetTransaction(%s) => %v %v", approval.TransactionHash, btx, err)
	if err != nil && !strings.Contains(err.Error(), "No such mempool or blockchain transaction") {
		return err
	}
	if btx != nil {
		return node.store.FinishTransactionSignatures(ctx, approval.TransactionHash, approval.RawTransaction)
	}

	signed, err := node.bitcoinCheckKeeperSignedTransaction(ctx, approval)
	if err != nil || signed {
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(approval.Signature)
	if err != nil {
		panic(err)
	}
	tx, err := node.keeperStore.ReadTransaction(ctx, approval.TransactionHash)
	if err != nil {
		return err
	}
	id := mixin.UniqueConversationID(approval.TransactionHash, approval.TransactionHash)
	rid := uuid.Must(uuid.FromString(tx.RequestId))
	extra := append(rid.Bytes(), sig...)
	action := common.ActionBitcoinSafeApproveTransaction
	err = node.sendBitcoinKeeperResponse(ctx, tx.Holder, byte(action), id, extra)
	if err != nil {
		return err
	}

	if approval.UpdatedAt.Add(keeper.SafeSignatureTimeout * 2).After(time.Now()) {
		return nil
	}
	id = mixin.UniqueConversationID(id, approval.UpdatedAt.String())
	err = node.sendBitcoinKeeperResponse(ctx, tx.Holder, byte(action), id, extra)
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
		signed[r.OutputIndex] = common.DecodeHexOrPanic(r.Signature.String)
	}

	b := common.DecodeHexOrPanic(approval.RawTransaction)
	psbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)
	msgTx := psbt.MsgTx()
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
