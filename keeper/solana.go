package keeper

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	sg "github.com/gagliardetto/solana-go"
)

func (node *Node) processSolanaSafeProposeAccount(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleHolder {
		panic(req.Role)
	}

	switch req.Curve {
	case common.CurveEdwards25519Default:
	default:
		panic(req.Curve)
	}

	rce := req.ExtraBytes()
	ver, _ := node.group.ReadKernelTransactionUntilSufficient(ctx, req.MixinHash.String())
	if len(rce) == 32 && len(ver.References) == 1 && bytes.Equal(ver.References[0][:], rce) {
		stx, _ := node.group.ReadKernelTransactionUntilSufficient(ctx, ver.References[0].String())
		rce = stx.Extra
	}

	arp, err := req.ParseMixinRecipient(ctx, node.mixin, rce)
	logger.Printf("req.ParseMixinRecipient(%v) => %v %v", req, arp, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}

	chain := common.SafeCurveChain(req.Curve)

	plan, err := node.store.ReadLatestOperationParams(ctx, chain, req.CreatedAt)
	logger.Printf("store.ReadLatestOperationParams(%d) => %v %v", chain, plan, err)
	if err != nil {
		panic(fmt.Errorf("node.ReadLatestOperationParams(%d) => %v", chain, err))
	} else if plan == nil || !plan.OperationPriceAmount.IsPositive() {
		return node.refundAndFailRequest(ctx, req, arp.Receivers, int(arp.Threshold))
	}
	if req.AssetId != plan.OperationPriceAsset {
		return node.failRequest(ctx, req, "")
	}
	if req.Amount.Cmp(plan.OperationPriceAmount) < 0 {
		return node.failRequest(ctx, req, "")
	}

	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err))
	} else if safe != nil {
		// safe already exists
		return node.failRequest(ctx, req, "")
	}

	if old, err := node.store.ReadSafeProposal(ctx, req.Id); err != nil {
		panic(fmt.Errorf("store.ReadSafeProposal(%s) => %v", req.Id, err))
	} else if old != nil {
		// safe proposal already exists
		return node.failRequest(ctx, req, "")
	}

	signer, observer, err := node.store.AssignSignerAndObserverToHolder(ctx, req, SafeKeyBackupMaturity, arp.Observer)
	logger.Printf("store.AssignSignerAndObserverToHolder(%s) => %s %s %v", req.Holder, signer, observer, err)
	if err != nil {
		panic(fmt.Errorf("store.AssignSignerAndObserverToHolder(%v) => %v", req, err))
	}

	if signer == "" || observer == "" {
		return node.refundAndFailRequest(ctx, req, arp.Receivers, int(arp.Threshold))
	}

	if arp.Observer != "" && arp.Observer != observer {
		panic(fmt.Errorf("store.AssignSignerAndObserverToHolder(%v) => %v %s", req, arp, observer))
	}

	if !common.CheckUnique(req.Holder, signer, observer) {
		return node.refundAndFailRequest(ctx, req, arp.Receivers, int(arp.Threshold))
	}

	client := node.solanaClient()
	payer := sg.MustPrivateKeyFromBase58(node.conf.SolanaPayerPrivateKey)
	ms, st, err := client.BuildSquadsSafe(ctx, sg.MPK(req.Holder), sg.MPK(signer), sg.MPK(observer), payer)
	logger.Printf("solana.BuildSquadsSafe(%v) => %v %v", req, ms, err)
	if err != nil {
		panic(err)
	}

	address := solana.GetMultisigPDA(ms.CreateKey)
	if old, err := node.store.ReadSafeProposalByAddress(ctx, address.String()); err != nil {
		panic(fmt.Errorf("store.ReadSafeProposalByAddress(%s) => %v", address, err))
	} else if old != nil {
		return node.failRequest(ctx, req, "")
	}

	raw, err := st.MarshalBinary()
	logger.Printf("solana.Transaction.MarshalBinary(%v) => %v %v", st, raw, err)
	if err != nil {
		panic(err)
	}

	tx := &store.Transaction{
		TransactionHash: st.Message.RecentBlockhash.String(),
		RawTransaction:  hex.EncodeToString(raw),
		Holder:          req.Holder,
		Chain:           chain,
		AssetId:         common.SafeSolanaChainId,
		State:           common.RequestStateInitial,
		Data:            "",
		RequestId:       req.Id,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
}

func (node *Node) processSolanaSafeSignatureResponse(ctx context.Context, req *common.Request, safe *store.Safe, tx *store.Transaction, old *store.SignatureRequest) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleSigner {
		panic(req.Role)
	}

	if safe.State != SafeStateApproved {
		return node.failRequest(ctx, req, "")
	}

	// verify signature from req
	{
		signer := sg.MustPublicKeyFromBase58(safe.Signer)
		sig := sg.SignatureFromBytes(req.ExtraBytes())
		msg := common.DecodeHexOrPanic(old.Message)
		if !signer.Verify(msg, sig) {
			logger.Printf("solana.signer.Verify(%v, %v) => false", msg, sig)
			return node.failRequest(ctx, req, "")
		}
	}

	err := node.store.FinishSignatureRequest(ctx, req)
	logger.Printf("store.FinishSignatureRequest(%s) => %v", req.Id, err)
	if err != nil {
		panic(fmt.Errorf("store.FinishSignatureRequest(%s) => %v", req.Id, err))
	}

	rawB := common.DecodeHexOrPanic(tx.RawTransaction)
	t, err := sg.TransactionFromBytes(rawB)
	logger.Printf("solana.TransactionFromBytes(%v) => %v %v", rawB, t, err)
	if err != nil {
		panic(err)
	}

	requests, err := node.store.ListAllSignaturesForTransaction(ctx, old.TransactionHash, common.RequestStatePending)
	logger.Printf("store.ListAllSignaturesForTransaction(%s) => %d %v", old.TransactionHash, len(requests), err)
	if err != nil {
		panic(fmt.Errorf("store.ListAllSignaturesForTransaction(%s) => %v", old.TransactionHash, err))
	}
	if len(requests) != 1 {
		panic(fmt.Errorf("invalid signature requests len: %d", len(requests)))
	}

	for i, signer := range t.Message.Signers() {
		if signer.String() != safe.Signer {
			continue
		}

		sig := sg.SignatureFromBytes(common.DecodeHexOrPanic(requests[0].Signature.String))
		msg, err := t.Message.MarshalBinary()
		if err != nil {
			panic(err)
		}

		if !signer.Verify(msg, sig) {
			panic(requests[0].Signature.String)
		}
		t.Signatures[i] = sig
	}

	raw, err := t.MarshalBinary()
	logger.Printf("solana.Transaction.MarshalBinary(%v) => %v %v", t, raw, err)
	if err != nil {
		panic(err)
	}

	sbm, err := node.store.ReadAllSolanaTokenBalancesMap(ctx, safe.Address)
	logger.Printf("store.ReadAllSolanaTokenBalancesMap(%s) => %v %v", safe.Address, sbm, err)
	if err != nil {
		panic(err)
	}

	outputs := solana.ExtractOutputs(t)
	for _, o := range outputs {
		closeBalance := big.NewInt(0).Sub(sbm[o.TokenAddress].BigBalance(), o.Amount)
		if closeBalance.Cmp(big.NewInt(0)) < 0 {
			logger.Printf("safe %s close balance %d lower than 0", safe.Address, closeBalance)
			return node.failRequest(ctx, req, "")
		}
		sbm[o.TokenAddress].UpdateBalance(new(big.Int).Neg(o.Amount))
	}

	stx := node.buildStorageTransaction(ctx, req, []byte(common.Base91Encode(raw)))
	if stx == nil {
		return node.failRequest(ctx, req, "")
	}
	txs := []*mtg.Transaction{stx}

	id := common.UniqueId(old.TransactionHash, stx.TraceId)
	typ := byte(common.ActionSolanaSafeApproveTransaction)
	crv := common.SafeChainCurve(safe.Chain)
	tt := node.buildObserverResponseWithStorageTraceId(ctx, id, req.Output, typ, crv, stx.TraceId)
	if tt == nil {
		return node.failRequest(ctx, req, "")
	}
	txs = append(txs, tt)

	err = node.store.FinishTransactionSignaturesWithRequest(ctx, old.TransactionHash, hex.EncodeToString(raw), req, 0, safe, sbm, txs)
	logger.Printf("store.FinishTransactionSignaturesWithRequest(%s, %s, %v) => %v", old.TransactionHash, raw, req, err)
	if err != nil {
		panic(err)
	}
	return txs, ""
}
