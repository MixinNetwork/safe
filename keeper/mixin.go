package keeper

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/mixin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

// We will always only allow XIN deposit for mixin kernel, because this is the only use case.
// But all code should imply more assets may come in the future. We make this decision, because
// the native chain safe is feasible for all other assets.
func (node *Node) doMixinKernelHolderDeposit(ctx context.Context, req *common.Request, deposit *Deposit, safe *store.Safe, bondId string, minimum decimal.Decimal) error {
	if deposit.Asset != SafeMixinKernelAssetId {
		return node.store.FailRequest(ctx, req.Id)
	}
	old, _, err := node.store.ReadMixinKernelUTXO(ctx, deposit.Hash, int(deposit.Index))
	logger.Printf("store.ReadMixinKernelUTXO(%s, %d) => %v %v", deposit.Hash, deposit.Index, old, err)
	if err != nil {
		return fmt.Errorf("store.ReadMixinKernelUTXO(%s, %d) => %v", deposit.Hash, deposit.Index, err)
	} else if old != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	dh, err := crypto.HashFromString(deposit.Hash)
	if err != nil {
		panic(err)
	}
	mtx, err := common.ReadKernelTransaction(node.conf.MixinRPC, dh)
	if err != nil {
		return fmt.Errorf("common.ReadKernelTransaction(%s) => %v", deposit.Hash, err)
	}

	amount := decimal.NewFromBigInt(deposit.Amount, -mixin.ValuePrecision)
	change, err := node.checkMixinKernelChange(ctx, deposit, mtx)
	logger.Printf("node.checkMixinKernelChange(%v, %v) => %t %v", deposit, mtx, change, err)
	if err != nil {
		return fmt.Errorf("node.checkMixinKernelChange(%v) => %v", deposit, err)
	}
	if amount.Cmp(minimum) < 0 && !change {
		return node.store.FailRequest(ctx, req.Id)
	}
	if amount.Cmp(decimal.New(mixin.ValueDust, -mixin.ValuePrecision)) < 0 {
		panic(deposit.Hash)
	}

	output, err := node.verifyMixinKernelTransaction(ctx, req, deposit, mtx, safe)
	logger.Printf("node.verifyMixinKernelTransaction(%v) => %v %v", req, output, err)
	if err != nil {
		return fmt.Errorf("node.verifyMixinKernelTransaction(%s) => %v", deposit.Hash, err)
	}
	if output == nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	if !change {
		err = node.buildTransaction(ctx, bondId, safe.Receivers, int(safe.Threshold), amount.String(), nil, req.Id)
		if err != nil {
			return fmt.Errorf("node.buildTransaction(%v) => %v", req, err)
		}
	}

	return node.store.WriteMixinKernelOutputFromRequest(ctx, safe.Address, deposit.Asset, output, req)
}

// holder key just for safe verification, not for kernel
// the kernel view key is derived by hash of holder, signer and observer
// then keeper and observer must never disclose the observer public key
// thus the kernel view key remains anonymous from public
func (node *Node) processMixinKernelSafeProposeAccount(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleHolder {
		panic(req.Role)
	}
	if req.Curve != common.CurveEdwards25519Mixin {
		panic(req.Curve)
	}
	chain := byte(SafeChainMixinKernel)
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

	acc := mixin.BuildAddress(req.Holder, signer, observer)
	logger.Verbosef("mixin.BuildAddress(%v) => %v", req, acc)
	old, err = node.store.ReadSafeProposalByAddress(ctx, acc.String())
	if err != nil {
		return fmt.Errorf("store.ReadSafeProposalByAddress(%s) => %v", acc.String(), err)
	} else if old != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	exk := node.writeStorageUntilSnapshot(ctx, []byte(common.Base91Encode([]byte(acc.String()))))
	typ := byte(common.ActionMixinKernelSafeProposeAccount)
	err = node.sendObserverResponseWithReferences(ctx, req.Id, typ, req.Curve, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", req.Id, exk, err)
	}

	path := mixinDefaultDerivationPath()
	sp := &store.SafeProposal{
		RequestId: req.Id,
		Chain:     chain,
		Holder:    req.Holder,
		Signer:    signer,
		Observer:  observer,
		Timelock:  arp.Timelock,
		Path:      hex.EncodeToString(path),
		Address:   acc.String(),
		Extra:     acc.PrivateViewKey[:],
		Receivers: arp.Receivers,
		Threshold: arp.Threshold,
		CreatedAt: req.CreatedAt,
		UpdatedAt: req.CreatedAt,
	}
	return node.store.WriteSafeProposalWithRequest(ctx, sp)
}

func (node *Node) processMixinKernelSafeApproveAccount(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	if req.Curve != common.CurveEdwards25519Mixin {
		panic(req.Curve)
	}
	chain := byte(SafeChainMixinKernel)
	old, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	} else if old != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) != 16+64 {
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

	ms := fmt.Sprintf("APPROVE:%s:%s", rid.String(), sp.Address)
	msg := mixin.HashMessageForSignature(ms)
	err = mixin.VerifySignature(req.Holder, msg, extra[16:])
	logger.Printf("mixin.VerifySignature(%v) => %v", req, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	spr, err := node.store.ReadRequest(ctx, sp.RequestId)
	if err != nil {
		return fmt.Errorf("store.ReadRequest(%s) => %v", sp.RequestId, err)
	}
	exk := node.writeStorageUntilSnapshot(ctx, []byte(common.Base91Encode([]byte(sp.Address))))
	typ := byte(common.ActionMixinKernelSafeApproveAccount)
	err = node.sendObserverResponseWithAssetAndReferences(ctx, req.Id, typ, req.Curve, spr.AssetId, spr.Amount.String(), exk)
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
		State:     SafeStateApproved,
		CreatedAt: req.CreatedAt,
		UpdatedAt: req.CreatedAt,
	}
	return node.store.WriteSafeWithRequest(ctx, safe)
}

func (node *Node) processMixinKernelSafeCloseAccount(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	panic(0)
}

func (node *Node) processMixinKernelSafeProposeTransaction(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleHolder {
		panic(req.Role)
	}
	if req.Curve != common.CurveEdwards25519Mixin {
		panic(req.Curve)
	}
	chain := byte(SafeChainMixinKernel)
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	}
	if safe == nil || safe.Chain != chain {
		return node.store.FailRequest(ctx, req.Id)
	}
	if safe.State != SafeStateApproved {
		return node.store.FailRequest(ctx, req.Id)
	}

	meta, err := node.fetchAssetMeta(ctx, req.AssetId)
	logger.Printf("node.fetchAssetMeta(%s) => %v %v", req.AssetId, meta, err)
	if err != nil {
		return fmt.Errorf("node.fetchAssetMeta(%s) => %v", req.AssetId, err)
	}
	if meta.Chain != SafeChainMVM {
		return node.store.FailRequest(ctx, req.Id)
	}
	deployed, err := abi.CheckFactoryAssetDeployed(node.conf.MVMRPC, meta.AssetKey)
	logger.Printf("abi.CheckFactoryAssetDeployed(%s) => %v %v", meta.AssetKey, deployed, err)
	if err != nil {
		return fmt.Errorf("api.CheckFatoryAssetDeployed(%s) => %v", meta.AssetKey, err)
	}
	if deployed.Sign() <= 0 {
		return node.store.FailRequest(ctx, req.Id)
	}
	assetId := uuid.Must(uuid.FromBytes(deployed.Bytes()))

	plan, err := node.store.ReadLatestOperationParams(ctx, safe.Chain, req.CreatedAt)
	logger.Printf("store.ReadLatestOperationParams(%d) => %v %v", safe.Chain, plan, err)
	if err != nil {
		return fmt.Errorf("store.ReadLatestOperationParams(%d) => %v", safe.Chain, err)
	} else if plan == nil || !plan.TransactionMinimum.IsPositive() {
		return node.refundAndFailRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}
	if req.Amount.Cmp(plan.TransactionMinimum) < 0 {
		return node.store.FailRequest(ctx, req.Id)
	}

	bondId, _, err := node.getBondAsset(ctx, assetId.String(), req.Holder)
	logger.Printf("node.getBondAsset(%s, %s) => %s %v", assetId.String(), req.Holder, bondId, err)
	if err != nil {
		return fmt.Errorf("node.getBondAsset(%s, %s) => %v", assetId.String(), req.Holder, err)
	}
	if crypto.NewHash([]byte(req.AssetId)) != bondId {
		return node.store.FailRequest(ctx, req.Id)
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) < 33 {
		return node.store.FailRequest(ctx, req.Id)
	}

	switch extra[0] {
	case common.FlagProposeNormalTransaction:
	case common.FlagProposeRecoveryTransaction:
	default:
		return node.store.FailRequest(ctx, req.Id)
	}
	extra = extra[1:]

	var outputs []*mixin.Output
	ver, _ := common.ReadKernelTransaction(node.conf.MixinRPC, req.MixinHash)
	if len(extra) == 32 && len(ver.References) == 1 && ver.References[0].String() == hex.EncodeToString(extra) {
		stx, _ := common.ReadKernelTransaction(node.conf.MixinRPC, ver.References[0])
		extra := common.DecodeMixinObjectExtra(stx.Extra)
		var recipients [][2]string // TODO better encoding
		err = json.Unmarshal(extra, &recipients)
		if err != nil {
			return node.store.FailRequest(ctx, req.Id)
		}
		var total decimal.Decimal
		for _, rp := range recipients {
			addr, err := mixin.ParseAddress(rp[0])
			logger.Printf("mixin.ParseAddress(%s) => %v %v", string(extra), addr, err)
			if err != nil {
				return node.store.FailRequest(ctx, req.Id)
			}
			amt, err := decimal.NewFromString(rp[1])
			if err != nil {
				return node.store.FailRequest(ctx, req.Id)
			}
			if amt.Cmp(plan.TransactionMinimum) < 0 {
				return node.store.FailRequest(ctx, req.Id)
			}
			total = total.Add(amt)
			outputs = append(outputs, &mixin.Output{
				Address: addr,
				Amount:  amt,
			})
		}
		if !total.Equal(req.Amount) {
			return node.store.FailRequest(ctx, req.Id)
		}
	} else {
		addr, err := mixin.ParseAddress(string(extra[16:]))
		logger.Printf("mixin.ParseAddress(%s) => %v %v", string(extra), addr, err)
		if err != nil {
			return node.store.FailRequest(ctx, req.Id)
		}
		outputs = append(outputs, &mixin.Output{
			Address: addr,
			Amount:  req.Amount,
		})
	}

	allInputs, err := node.store.ListAllMixinKernelUTXOsForHolderAndAsset(ctx, safe.Holder, assetId.String())
	if err != nil {
		return fmt.Errorf("store.ListAllMixinKernelUTXOsForHolderAndAsset(%s, %s) => %v", req.Holder, assetId.String(), err)
	}
	psbt, err := mixin.BuildPartiallySignedTransaction(allInputs, outputs, req.Id, safe.Holder, safe.Signer, safe.Observer)
	logger.Printf("mixin.BuildPartiallySignedTransaction(%v) => %v %v", req, psbt, err)
	if bitcoin.IsInsufficientInputError(err) {
		return node.refundAndFailRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}
	if err != nil {
		return fmt.Errorf("mixin.BuildPartiallySignedTransaction(%v) => %v", req, err)
	}

	msg := common.Base91Encode(psbt.PayloadMarshal())
	exk := node.writeStorageUntilSnapshot(ctx, []byte(msg))
	typ := byte(common.ActionMixinKernelSafeProposeTransaction)
	err = node.sendObserverResponseWithReferences(ctx, req.Id, typ, req.Curve, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", req.Id, exk, err)
	}

	total := decimal.Zero
	recipients := make([]map[string]string, len(outputs))
	for i, out := range outputs {
		recipients[i] = map[string]string{
			"receiver": out.Address.String(),
			"amount":   out.Amount.String(),
		}
		total = total.Add(out.Amount)
	}
	if !total.Equal(req.Amount) {
		return node.store.FailRequest(ctx, req.Id)
	}
	data := common.MarshalJSONOrPanic(map[string]any{
		"recipients": recipients,
		"storage":    exk,
	})
	tx := &store.Transaction{
		TransactionHash: psbt.PayloadHash().String(),
		RawTransaction:  hex.EncodeToString(psbt.PayloadMarshal()),
		Holder:          req.Holder,
		Chain:           safe.Chain,
		AssetId:         assetId.String(),
		State:           common.RequestStateInitial,
		Data:            string(data),
		RequestId:       req.Id,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	inputs := make([]*store.TransactionInput, len(psbt.Inputs))
	for i, in := range psbt.Inputs {
		inputs[i] = &store.TransactionInput{
			Hash:  in.Hash.String(),
			Index: uint32(in.Index),
		}
	}
	return node.store.WriteTransactionWithRequest(ctx, tx, inputs)
}

func (node *Node) processMixinKernelSafeRevokeTransaction(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	if req.Curve != common.CurveEdwards25519Mixin {
		panic(req.Curve)
	}
	chain := byte(SafeChainMixinKernel)
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	}
	if safe == nil || safe.Chain != chain {
		return node.store.FailRequest(ctx, req.Id)
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) < 64 {
		return node.store.FailRequest(ctx, req.Id)
	}
	rid, err := uuid.FromBytes(extra[:16])
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	tx, err := node.store.ReadTransactionByRequestId(ctx, rid.String())
	if err != nil {
		return fmt.Errorf("store.ReadTransactionByRequestId(%v) => %s %v", req, rid.String(), err)
	} else if tx == nil {
		return node.store.FailRequest(ctx, req.Id)
	} else if tx.Holder != req.Holder {
		return node.store.FailRequest(ctx, req.Id)
	} else if tx.State != common.RequestStateInitial {
		return node.store.FailRequest(ctx, req.Id)
	}

	ms := fmt.Sprintf("REVOKE:%s:%s", rid.String(), tx.TransactionHash)
	msg := mixin.HashMessageForSignature(ms)
	err = mixin.VerifySignature(req.Holder, msg, extra[16:])
	logger.Printf("holder: mixin.VerifySignature(%v) => %v", req, err)
	if err != nil {
		err = mixin.VerifySignature(safe.Observer, msg, extra[16:])
		logger.Printf("observer: mixin.VerifySignature(%v) => %v", req, err)
		if err != nil {
			return node.store.FailRequest(ctx, req.Id)
		}
	}

	bondId, _, err := node.getBondAsset(ctx, tx.AssetId, safe.Holder)
	logger.Printf("node.getBondAsset(%s, %s) => %s %v", tx.AssetId, req.Holder, bondId, err)
	if err != nil {
		return fmt.Errorf("node.getBondAsset(%s, %s) => %v", tx.AssetId, req.Holder, err)
	}
	var data struct {
		Recipients []map[string]string `json:"recipients"`
	}
	err = json.Unmarshal([]byte(tx.Data), &data)
	if err != nil {
		panic(err)
	}
	amount := decimal.Zero
	for _, t := range data.Recipients {
		ta := decimal.RequireFromString(t["amount"])
		if ta.Cmp(decimal.NewFromFloat(0.0001)) < 0 {
			panic(tx.Data)
		}
		amount = amount.Add(ta)
	}
	meta, err := node.fetchAssetMeta(ctx, bondId.String())
	logger.Printf("node.fetchAssetMeta(%s) => %v %v", bondId.String(), meta, err)
	if err != nil {
		return fmt.Errorf("node.fetchAssetMeta(%s) => %v", bondId.String(), err)
	}
	if meta.Chain != SafeChainMVM {
		return node.store.FailRequest(ctx, req.Id)
	}
	err = node.buildTransaction(ctx, meta.AssetId, safe.Receivers, int(safe.Threshold), amount.String(), nil, req.Id)
	if err != nil {
		return err
	}

	return node.store.RevokeTransactionWithRequest(ctx, tx, safe, req)
}

func (node *Node) processMixinKernelSafeApproveTransaction(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	if req.Curve != common.CurveEdwards25519Mixin {
		panic(req.Curve)
	}
	chain := byte(SafeChainMixinKernel)
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	}
	if safe == nil || safe.Chain != chain {
		return node.store.FailRequest(ctx, req.Id)
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) != 16+64 {
		return node.store.FailRequest(ctx, req.Id)
	}
	rid, err := uuid.FromBytes(extra[:16])
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	tx, err := node.store.ReadTransactionByRequestId(ctx, rid.String())
	if err != nil {
		return fmt.Errorf("store.ReadTransactionByRequestId(%v) => %s %v", req, rid.String(), err)
	} else if tx == nil {
		return node.store.FailRequest(ctx, req.Id)
	} else if tx.Holder != req.Holder {
		return node.store.FailRequest(ctx, req.Id)
	}

	ms := fmt.Sprintf("APPROVE:%s:%s", rid.String(), tx.TransactionHash)
	msg := mixin.HashMessageForSignature(ms)
	err = mixin.VerifySignature(tx.Holder, msg, extra[16:])
	logger.Printf("mixin.VerifySignature(%v) => %v", req, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	var data struct {
		StorageTransaction crypto.Hash `json:"storage"`
	}
	err = json.Unmarshal([]byte(tx.Data), &data)
	if err != nil {
		panic(err)
	}

	raw := common.DecodeHexOrPanic(tx.RawTransaction)
	psbt, err := mixin.ParsePartiallySignedTransaction(raw)
	if err != nil {
		panic(err)
	}
	addr := mixin.BuildAddress(safe.Holder, safe.Signer, safe.Observer)
	var requests []*store.SignatureRequest
	for idx, in := range psbt.Inputs {
		pending, err := node.checkTransactionIndexSignaturePending(ctx, tx.TransactionHash, idx, req)
		logger.Printf("node.checkTransactionIndexSignaturePending(%s, %d) => %t %v", tx.TransactionHash, idx, pending, err)
		if err != nil {
			return err
		} else if pending {
			continue
		}

		utxo, _, _ := node.store.ReadMixinKernelUTXO(ctx, in.Hash.String(), in.Index)
		r := crypto.KeyMultPubPriv(&utxo.Mask, &addr.PrivateViewKey)
		msg := crypto.HashScalar(r, uint64(in.Index)).Bytes()
		msg = append(msg, data.StorageTransaction[:]...)

		sr := &store.SignatureRequest{
			TransactionHash: tx.TransactionHash,
			InputIndex:      idx,
			Signer:          safe.Signer,
			Curve:           req.Curve,
			Message:         hex.EncodeToString(msg),
			State:           common.RequestStateInitial,
			CreatedAt:       req.CreatedAt,
			UpdatedAt:       req.CreatedAt,
		}
		sr.RequestId = common.UniqueId(req.Id, sr.Message)
		requests = append(requests, sr)
	}
	err = node.store.WriteSignatureRequestsWithRequest(ctx, requests, tx.TransactionHash, req)
	logger.Printf("store.WriteSignatureRequestsWithRequest(%s, %d, %v) => %v", tx.TransactionHash, len(requests), req, err)
	if err != nil {
		return fmt.Errorf("store.WriteSignatureRequestsWithRequest(%s) => %v", tx.TransactionHash, err)
	}

	for _, sr := range requests {
		err := node.sendSignerSignRequest(ctx, sr, safe.Path)
		if err != nil {
			return fmt.Errorf("node.sendSignerSignRequest(%v) => %v", sr, err)
		}
	}
	return nil
}

func (node *Node) processMixinKernelSafeSignatureResponse(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleSigner {
		panic(req.Role)
	}
	if req.Curve != common.CurveEdwards25519Mixin {
		panic(req.Curve)
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
	safe, err := node.store.ReadSafe(ctx, tx.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", tx.Holder, err)
	}
	if safe.Signer != req.Holder {
		return node.store.FailRequest(ctx, req.Id)
	}

	raw := common.DecodeHexOrPanic(tx.RawTransaction)
	sig, _ := hex.DecodeString(req.Extra)
	msg := common.DecodeHexOrPanic(old.Message)
	spk := mixin.DeriveKey(safe.Signer, msg[:32])
	err = mixin.VerifySignature(spk, raw, sig)
	logger.Printf("mixin.VerifySignature(%v) => %v", req, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	err = node.store.FinishSignatureRequest(ctx, req)
	logger.Printf("store.FinishSignatureRequest(%s) => %v", req.Id, err)
	if err != nil {
		return fmt.Errorf("store.FinishSignatureRequest(%s) => %v", req.Id, err)
	}

	requests, err := node.store.ListAllSignaturesForTransaction(ctx, old.TransactionHash, common.RequestStatePending)
	logger.Printf("store.ListAllSignaturesForTransaction(%s) => %d %v", old.TransactionHash, len(requests), err)
	if err != nil {
		return fmt.Errorf("store.ListAllSignaturesForTransaction(%s) => %v", old.TransactionHash, err)
	}

	psbt, err := mixin.ParsePartiallySignedTransaction(raw)
	if err != nil {
		panic(err)
	}
	for idx := range psbt.Inputs {
		sr := requests[idx]
		if sr == nil {
			return node.store.FailRequest(ctx, req.Id)
		}
		msg := common.DecodeHexOrPanic(sr.Message)
		sig := common.DecodeHexOrPanic(sr.Signature.String)
		spk := mixin.DeriveKey(safe.Signer, msg[:32])
		err = mixin.VerifySignature(spk, raw, sig)
		if err != nil {
			panic(sr.Signature.String)
		}
		var msig crypto.Signature
		copy(msig[:], sig)
		psbt.SignaturesMap = append(psbt.SignaturesMap, map[uint16]*crypto.Signature{0: &msig})
	}

	exk := node.writeStorageUntilSnapshot(ctx, []byte(common.Base91Encode(psbt.Marshal())))
	id := common.UniqueId(old.TransactionHash, hex.EncodeToString(exk[:]))
	typ := byte(common.ActionMixinKernelSafeApproveTransaction)
	err = node.sendObserverResponseWithReferences(ctx, id, typ, req.Curve, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", id, exk, err)
	}
	signed := hex.EncodeToString(psbt.Marshal())
	err = node.store.FinishTransactionSignaturesWithRequest(ctx, old.TransactionHash, signed, req, int64(len(psbt.Inputs)), safe)
	logger.Printf("store.FinishTransactionSignaturesWithRequest(%s, %s, %v) => %v", old.TransactionHash, signed, req, err)
	return err
}

func (node *Node) checkMixinKernelChange(ctx context.Context, deposit *Deposit, mtx *common.VersionedTransaction) (bool, error) {
	vin, spentBy, err := node.store.ReadMixinKernelUTXO(ctx, mtx.Inputs[0].Hash.String(), mtx.Inputs[0].Index)
	if err != nil || vin == nil {
		return false, err
	}
	tx, err := node.store.ReadTransaction(ctx, spentBy)
	if err != nil {
		return false, err
	}
	var recipients []map[string]string
	err = json.Unmarshal([]byte(tx.Data), &recipients)
	if err != nil || len(recipients) == 0 {
		return false, fmt.Errorf("store.ReadTransaction(%s) => %s", spentBy, tx.Data)
	}
	return deposit.Index >= uint64(len(recipients)), nil
}

func (node *Node) verifyMixinKernelTransaction(ctx context.Context, req *common.Request, deposit *Deposit, mtx *common.VersionedTransaction, safe *store.Safe) (*mixin.Input, error) {
	input, receiver := mixin.ParseTransactionDepositOutput(safe.Holder, safe.Signer, safe.Observer, mtx, int(deposit.Index))
	if input == nil {
		return nil, fmt.Errorf("malicious mixin kernel deposit or node not in sync? %s %d", deposit.Hash, deposit.Index)
	}
	if input.Asset != crypto.NewHash([]byte(deposit.Asset)) {
		return nil, fmt.Errorf("malicious mixin kernel deposit asset %s %d", deposit.Hash, deposit.Index)
	}

	if !input.Amount.Equal(decimal.NewFromBigInt(deposit.Amount, -mixin.ValuePrecision)) {
		return nil, fmt.Errorf("malicious mixin kernel deposit amount %s %d", deposit.Hash, deposit.Index)
	}
	if safe.Address != receiver {
		return nil, fmt.Errorf("malicious mixin kernel deposit address %s %d", deposit.Hash, deposit.Index)
	}

	return input, nil
}
