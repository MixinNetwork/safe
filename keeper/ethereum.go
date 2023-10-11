package keeper

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/gofrs/uuid/v5"
)

func (node *Node) processEthereumSafeProposeAccount(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleHolder {
		panic(req.Role)
	}
	switch req.Curve {
	case common.CurveSecp256k1ECDSAEthereum, common.CurveSecp256k1ECDSAMVM:
	default:
		panic(req.Curve)
	}
	rce, err := hex.DecodeString(req.Extra)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	ver, _ := common.ReadKernelTransaction(node.conf.MixinRPC, req.MixinHash)
	if len(rce) == 32 && len(ver.References) == 1 && ver.References[0].String() == req.Extra {
		stx, _ := common.ReadKernelTransaction(node.conf.MixinRPC, ver.References[0])
		rce = common.DecodeMixinObjectExtra(stx.Extra)
	}
	arp, err := req.ParseMixinRecipient(rce)
	logger.Printf("req.ParseMixinRecipient(%v) => %v %v", req, arp, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	chain := SafeCurveChain(req.Curve)

	plan, err := node.store.ReadLatestOperationParams(ctx, chain, req.CreatedAt)
	logger.Printf("store.ReadLatestOperationParams(%d) => %v %v", chain, plan, err)
	if err != nil {
		return fmt.Errorf("node.ReadLatestOperationParams(%d) => %v", chain, err)
	} else if plan == nil || !plan.OperationPriceAmount.IsPositive() {
		return node.refundAndFailRequest(ctx, req, arp.Receivers, int(arp.Threshold))
	}
	if req.AssetId != plan.OperationPriceAsset {
		return node.store.FailRequest(ctx, req.Id)
	}
	if req.Amount.Cmp(plan.OperationPriceAmount) < 0 {
		return node.store.FailRequest(ctx, req.Id)
	}
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	} else if safe != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	old, err := node.store.ReadSafeProposal(ctx, req.Id)
	if err != nil {
		return fmt.Errorf("store.ReadSafeProposal(%s) => %v", req.Id, err)
	} else if old != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	signer, observer, err := node.store.AssignSignerAndObserverToHolder(ctx, req, SafeKeyBackupMaturity, arp.Observer)
	logger.Printf("store.AssignSignerAndObserverToHolder(%s) => %s %s %v", req.Holder, signer, observer, err)
	if err != nil {
		return fmt.Errorf("store.AssignSignerAndObserverToHolder(%v) => %v", req, err)
	}
	if signer == "" || observer == "" {
		return node.refundAndFailRequest(ctx, req, arp.Receivers, int(arp.Threshold))
	}
	if arp.Observer != "" && arp.Observer != observer {
		return fmt.Errorf("store.AssignSignerAndObserverToHolder(%v) => %v %s", req, arp, observer)
	}
	if !common.CheckUnique(req.Holder, signer, observer) {
		return node.refundAndFailRequest(ctx, req, arp.Receivers, int(arp.Threshold))
	}

	rpc, assetId := node.ethereumParams(chain)
	gs, t, err := ethereum.BuildGnosisSafe(ctx, rpc, req.Holder, signer, observer, arp.Timelock, chain)
	logger.Verbosef("ethereum.BuildGnosisSafe(%v) => %v %v", req, gs, err)
	if err != nil {
		return err
	}
	old, err = node.store.ReadSafeProposalByAddress(ctx, gs.Address)
	if err != nil {
		return fmt.Errorf("store.ReadSafeProposalByAddress(%s) => %v", gs.Address, err)
	} else if old != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	tx := &store.Transaction{
		TransactionHash: hex.EncodeToString(t.Message),
		RawTransaction:  hex.EncodeToString(t.Marshal()),
		Holder:          req.Holder,
		Chain:           chain,
		AssetId:         assetId,
		State:           common.RequestStateInitial,
		Data:            "",
		RequestId:       req.Id,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	err = node.store.WriteInitialTransaction(ctx, tx)
	logger.Printf("store.WriteInitialTransaction(%v) => %v", tx, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	extra := gs.Marshal()
	exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(extra)))
	typ := byte(common.ActionEthereumSafeProposeAccount)
	crv := SafeChainCurve(chain)
	err = node.sendObserverResponseWithReferences(ctx, req.Id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", req.Id, exk, err)
	}

	path := ethereumDefaultDerivationPath()
	sp := &store.SafeProposal{
		RequestId: req.Id,
		Chain:     chain,
		Holder:    req.Holder,
		Signer:    signer,
		Observer:  observer,
		Timelock:  arp.Timelock,
		Path:      hex.EncodeToString(path),
		Address:   gs.Address,
		Extra:     extra,
		Receivers: arp.Receivers,
		Threshold: arp.Threshold,
		CreatedAt: req.CreatedAt,
		UpdatedAt: req.CreatedAt,
	}
	return node.store.WriteSafeProposalWithRequest(ctx, sp)
}

func (node *Node) processEthereumSafeApproveAccount(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	switch req.Curve {
	case common.CurveSecp256k1ECDSAEthereum, common.CurveSecp256k1ECDSAMVM:
	default:
		panic(req.Curve)
	}
	old, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	} else if old != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	chain := SafeChainCurve(req.Curve)

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) < 64 {
		return node.store.FailRequest(ctx, req.Id)
	}
	rid, err := uuid.FromBytes(extra[:16])
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	sp, err := node.store.ReadSafeProposal(ctx, rid.String())
	if err != nil {
		return fmt.Errorf("store.ReadSafeProposal(%v) => %s %v", req, rid.String(), err)
	} else if sp == nil {
		return node.store.FailRequest(ctx, req.Id)
	} else if sp.Holder != req.Holder {
		return node.store.FailRequest(ctx, req.Id)
	} else if sp.Chain != chain {
		return node.store.FailRequest(ctx, req.Id)
	}
	safe, err := node.store.ReadSafeByAddress(ctx, sp.Address)
	if err != nil {
		return fmt.Errorf("store.ReadSafeByAddress(%s) => %v %v", sp.Address, safe, err)
	}
	if safe != nil && safe.State == SafeStatePending {
		err = node.store.FinishSafeWithRequest(ctx, safe, req.Id)
		logger.Printf("store.FinishSafeWithRequest(%s) => %v %v", sp.Address, safe, err)
		return err
	}

	gsByte, err := common.Base91Decode(string(sp.Extra))
	logger.Printf("Base91Decode(%s) => %v %v", string(sp.Extra), gsByte, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	gs, err := ethereum.UnmarshalGnosisSafe(gsByte)
	logger.Printf("ethereum.UnmarshalGnosisSafe(%s) => %v %v", gsByte, gs, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	tx, err := node.store.ReadTransaction(ctx, gs.TxHash)
	logger.Printf("store.ReadTransaction(%s) => %v %v", gs.TxHash, tx, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	rawB, err := hex.DecodeString(tx.RawTransaction)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	t, err := ethereum.UnmarshalSafeTransaction(rawB)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%v) => %v %v", rawB, t, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	err = ethereum.VerifySignature(req.Holder, t.Message, extra[16:])
	logger.Printf("ethereum.VerifySignature(%v) => %v", req, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	_, pubs, err := ethereum.GetSortedSafeOwners(sp.Holder, sp.Signer, sp.Observer)
	logger.Printf("ethereum.GetSortedSafeOwners(%s, %s, %s) => %v, %v", sp.Holder, sp.Signer, sp.Observer, pubs, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	for i, pub := range pubs {
		if pub == sp.Holder {
			t.Signatures[i] = extra[16:]
		}
	}
	err = node.store.UpdateInitialTransactionWithRequest(ctx, tx.TransactionHash, hex.EncodeToString(t.Marshal()), req.Id)
	logger.Printf("store.WriteTransactionWithRequest(%v) => %v", tx, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	sr := &store.SignatureRequest{
		TransactionHash: tx.TransactionHash,
		InputIndex:      0,
		Signer:          sp.Signer,
		Curve:           req.Curve,
		Message:         tx.TransactionHash,
		State:           common.RequestStateInitial,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	sr.RequestId = common.UniqueId(req.Id, sr.Message)
	err = node.sendSignerSignRequest(ctx, sr, sp.Path)
	if err != nil {
		return fmt.Errorf("node.sendSignerSignRequest(%v) => %v", sr, err)
	}
	return nil
}

func (node *Node) processEthereumSafeSignatureResponse(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleSigner {
		panic(req.Role)
	}
	old, err := node.store.ReadSignatureRequest(ctx, req.Id)
	logger.Printf("store.ReadSignatureRequest(%s) => %v %v", req.Id, old, err)
	if err != nil {
		return fmt.Errorf("store.ReadSignatureRequest(%s) => %v", req.Id, err)
	}
	if old == nil || old.State == common.RequestStateDone {
		return node.store.FailRequest(ctx, req.Id)
	}
	tx, err := node.store.ReadTransaction(ctx, old.TransactionHash)
	if err != nil {
		return fmt.Errorf("store.ReadTransaction(%v) => %s %v", req, old.TransactionHash, err)
	}
	sp, err := node.store.ReadSafeProposal(ctx, tx.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafeProposal(%s) => %v", tx.Holder, err)
	}
	safe, err := node.store.ReadSafe(ctx, tx.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", tx.Holder, err)
	}
	if sp.Signer != req.Holder {
		return node.store.FailRequest(ctx, req.Id)
	}

	sig, _ := hex.DecodeString(req.Extra)
	msg := common.DecodeHexOrPanic(old.Message)
	err = ethereum.VerifySignature(sp.Signer, msg, sig)
	logger.Printf("node.VerifySignature(%v) => %v", req, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	err = node.store.FinishSignatureRequest(ctx, req)
	logger.Printf("store.FinishSignatureRequest(%s) => %v", req.Id, err)
	if err != nil {
		return fmt.Errorf("store.FinishSignatureRequest(%s) => %v", req.Id, err)
	}

	rawB, err := hex.DecodeString(tx.RawTransaction)
	logger.Printf("hex.DecodeString(%v) => %v %v", tx, rawB, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	t, err := ethereum.UnmarshalSafeTransaction(rawB)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%v) => %v %v", rawB, t, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	_, pubs, err := ethereum.GetSortedSafeOwners(sp.Holder, sp.Signer, sp.Observer)
	logger.Printf("ethereum.GetSortedSafeOwners(%v) => %v %v", sp, pubs, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, old.TransactionHash, common.RequestStatePending)
	logger.Printf("store.ListAllSignaturesForTransaction(%s) => %d %v", old.TransactionHash, len(requests), err)
	if err != nil {
		return fmt.Errorf("store.ListAllSignaturesForTransaction(%s) => %v", old.TransactionHash, err)
	}
	if len(requests) != 1 {
		return fmt.Errorf("Invalid signature requests len: %d", len(requests))
	}
	for i, pub := range pubs {
		if pub == sp.Signer {
			msg := t.Message
			sig := common.DecodeHexOrPanic(requests[0].Signature.String)
			err = ethereum.VerifySignature(sp.Signer, msg, sig)
			if err != nil {
				panic(requests[0].Signature.String)
			}
			t.Signatures[i] = sig
		}
	}
	raw := hex.EncodeToString(t.Marshal())
	err = node.store.FinishTransactionSignaturesWithRequest(ctx, old.TransactionHash, raw, req, 0, tx.Chain)
	logger.Printf("store.FinishTransactionSignaturesWithRequest(%s, %s, %v) => %v", old.TransactionHash, raw, req, err)

	if safe == nil {
		spr, err := node.store.ReadRequest(ctx, sp.RequestId)
		if err != nil {
			return fmt.Errorf("store.ReadRequest(%s) => %v", sp.RequestId, err)
		}
		exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(sp.Extra)))
		typ := byte(common.ActionEthereumSafeApproveAccount)
		crv := SafeChainCurve(sp.Chain)
		err = node.sendObserverResponseWithAssetAndReferences(ctx, req.Id, typ, crv, spr.AssetId, spr.Amount.String(), exk)
		if err != nil {
			return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", req.Id, exk, err)
		}

		safe := &store.Safe{
			Holder:    sp.Holder,
			Chain:     sp.Chain,
			Signer:    sp.Signer,
			Observer:  sp.Observer,
			Timelock:  sp.Timelock,
			Path:      sp.Path,
			Address:   sp.Address,
			Extra:     sp.Extra,
			Receivers: sp.Receivers,
			Threshold: sp.Threshold,
			RequestId: req.Id,
			State:     SafeStatePending,
			CreatedAt: req.CreatedAt,
			UpdatedAt: req.CreatedAt,
		}
		return node.store.WriteSafeWithRequest(ctx, safe)
	}

	exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(t.Marshal())))
	id := common.UniqueId(old.TransactionHash, hex.EncodeToString(exk[:]))
	typ := byte(common.ActionBitcoinSafeApproveTransaction)
	crv := SafeChainCurve(safe.Chain)
	err = node.sendObserverResponseWithReferences(ctx, id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", id, exk, err)
	}
	return nil
}
