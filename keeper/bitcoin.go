package keeper

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid"
	"github.com/shopspring/decimal"
)

func (node *Node) processBitcoinSafeProposeAccount(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleHolder {
		panic(req.Role)
	}
	receivers, threshold, err := req.ParseMixinRecipient()
	logger.Printf("req.ParseMixinRecipient(%v) => %v %d %v", req, receivers, threshold, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	chain := bitcoinCurveChain(req.Curve)

	plan, err := node.store.ReadAccountPlan(ctx, chain)
	logger.Printf("store.ReadAccountPlan(%d) => %v %v", chain, plan, err)
	if err != nil {
		return fmt.Errorf("node.ReadAccountPrice(%d) => %v", chain, err)
	} else if plan == nil || !plan.AccountPriceAmount.IsPositive() {
		return node.refundAndFailRequest(ctx, req, receivers, int(threshold))
	}
	if req.AssetId != plan.AccountPriceAsset {
		return node.store.FailRequest(ctx, req.Id)
	}
	if req.Amount.Cmp(plan.AccountPriceAmount) < 0 {
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

	signer, observer, accountant, err := node.store.AssignSignerAndObserverToHolder(ctx, req, SafeKeyBackupMaturity)
	logger.Printf("store.AssignSignerAndObserverToHolder(%s) => %s %s %s %v", req.Holder, signer, observer, accountant, err)
	if err != nil {
		return fmt.Errorf("store.AssignSignerAndObserverToHolder(%v) => %v", req, err)
	}
	if signer == "" || observer == "" || accountant == "" {
		return node.refundAndFailRequest(ctx, req, receivers, int(threshold))
	}
	if !common.CheckUnique(req.Holder, signer, observer, accountant) {
		return node.refundAndFailRequest(ctx, req, receivers, int(threshold))
	}
	timelock := node.bitcoinTimeLockDuration(ctx)
	wsa, err := bitcoin.BuildWitnessScriptAccount(req.Holder, signer, observer, timelock, chain)
	if err != nil {
		return fmt.Errorf("bitcoin.BuildWitnessScriptAccount(%s, %s, %s) => %v", req.Holder, signer, observer, err)
	}
	awka, err := bitcoin.BuildWitnessKeyAccount(accountant, chain)
	if err != nil {
		return fmt.Errorf("bitcoin.BuildWitnessKeyAccount(%s) => %v", accountant, err)
	}

	old, err = node.store.ReadSafeProposalByAddress(ctx, wsa.Address)
	if err != nil {
		return fmt.Errorf("store.ReadSafeProposalByAddress(%s) => %v", wsa.Address, err)
	} else if old != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	extra := wsa.MarshalWithAccountant(awka.Address)
	exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(extra)))
	typ := byte(common.ActionBitcoinSafeProposeAccount)
	crv := bitcoinChainCurve(chain)
	err = node.sendObserverResponseWithReferences(ctx, req.Id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverRespons(%s, %x) => %v", req.Id, exk, err)
	}

	sp := &store.SafeProposal{
		RequestId:  req.Id,
		Chain:      chain,
		Holder:     req.Holder,
		Signer:     signer,
		Observer:   observer,
		Timelock:   timelock,
		Accountant: accountant,
		Address:    wsa.Address,
		Extra:      extra,
		Receivers:  receivers,
		Threshold:  threshold,
		CreatedAt:  req.CreatedAt,
		UpdatedAt:  req.CreatedAt,
	}
	return node.store.WriteSafeProposalWithRequest(ctx, sp)
}

func (node *Node) processBitcoinSafeApproveAccount(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	old, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	} else if old != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	chain := bitcoinCurveChain(req.Curve)

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

	msg := bitcoin.HashMessageForSignature(sp.Address, sp.Chain)
	err = bitcoin.VerifySignatureDER(req.Holder, msg, extra[16:])
	logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", req, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	awka, err := bitcoin.BuildWitnessKeyAccount(sp.Accountant, sp.Chain)
	if err != nil {
		return fmt.Errorf("bitcoin.BuildWitnessKeyAccount(%s) => %v", sp.Accountant, err)
	}

	spr, err := node.store.ReadRequest(ctx, sp.RequestId)
	if err != nil {
		return fmt.Errorf("store.ReadRequest(%s) => %v", sp.RequestId, err)
	}
	exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(sp.Extra)))
	typ := byte(common.ActionBitcoinSafeApproveAccount)
	crv := bitcoinChainCurve(sp.Chain)
	err = node.sendObserverResponseWithAssetAndReferences(ctx, req.Id, typ, crv, spr.AssetId, spr.Amount.String(), exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverRespons(%s, %x) => %v", req.Id, exk, err)
	}

	safe := &store.Safe{
		Holder:     sp.Holder,
		Chain:      sp.Chain,
		Signer:     sp.Signer,
		Observer:   sp.Observer,
		Timelock:   sp.Timelock,
		Accountant: sp.Accountant,
		Address:    sp.Address,
		Extra:      sp.Extra,
		Receivers:  sp.Receivers,
		Threshold:  sp.Threshold,
		RequestId:  req.Id,
		CreatedAt:  req.CreatedAt,
		UpdatedAt:  req.CreatedAt,
	}
	return node.store.WriteSafeWithRequest(ctx, safe, awka.Address)
}

func (node *Node) processBitcoinSafeProposeTransaction(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleHolder {
		panic(req.Role)
	}
	chain := bitcoinCurveChain(req.Curve)
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	}
	if safe == nil || safe.Chain != chain {
		return node.store.FailRequest(ctx, req.Id)
	}

	assetId := SafeBitcoinChainId
	switch safe.Chain {
	case SafeChainBitcoin:
	case SafeChainLitecoin:
		assetId = SafeLitecoinChainId
	default:
		panic(safe.Chain)
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
	id := uuid.Must(uuid.FromBytes(deployed.Bytes()))
	if id.String() != assetId {
		return node.store.FailRequest(ctx, req.Id)
	}

	plan, err := node.store.ReadAccountPlan(ctx, safe.Chain)
	logger.Printf("store.ReadAccountPlan(%d) => %v %v", safe.Chain, plan, err)
	if err != nil {
		return fmt.Errorf("store.ReadAccountPlan(%d) => %v", safe.Chain, err)
	} else if plan == nil || !plan.TransactionMinimum.IsPositive() {
		return node.refundAndFailRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}
	if req.Amount.Cmp(plan.TransactionMinimum) < 0 {
		return node.store.FailRequest(ctx, req.Id)
	}

	bondId, _, err := node.getBondAsset(ctx, id.String(), req.Holder)
	logger.Printf("node.getBondAsset(%s, %s) => %s %v", id.String(), req.Holder, bondId, err)
	if err != nil {
		return fmt.Errorf("node.getBondAsset(%s, %s) => %v", id.String(), req.Holder, err)
	}
	if crypto.NewHash([]byte(req.AssetId)) != bondId {
		return node.store.FailRequest(ctx, req.Id)
	}

	balance, err := node.store.ReadAccountantBalance(ctx, req.Holder)
	logger.Printf("node.ReadAccountantBalance(%v) => %v %v", req.Holder, balance, err)
	if err != nil {
		return fmt.Errorf("store.ReadAccountantBalance(%s) => %v", req.Holder, err)
	}
	if balance.IsZero() {
		return node.refundAndFailRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) < 32 {
		return node.store.FailRequest(ctx, req.Id)
	}
	iid, err := uuid.FromBytes(extra[:16])
	if err != nil || iid.String() == uuid.Nil.String() {
		return node.store.FailRequest(ctx, req.Id)
	}
	receiver, err := bitcoin.ParseAddress(string(extra[16:]), safe.Chain)
	logger.Printf("bitcoin.ParseAddress(%s, %d) => %s %v", string(extra), safe.Chain, receiver, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	info, err := node.store.ReadNetworkInfo(ctx, iid.String())
	logger.Printf("store.ReadNetworkInfo(%s) => %v %v", iid.String(), info, err)
	if err != nil {
		return fmt.Errorf("store.ReadNetworkInfo(%s) => %v", iid.String(), err)
	}
	if info == nil || info.Chain != safe.Chain {
		return node.store.FailRequest(ctx, req.Id)
	}
	if info.CreatedAt.Add(SafeNetworkInfoTimeout * 30).Before(req.CreatedAt) {
		return node.refundAndFailRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}

	outputs := []*bitcoin.Output{{
		Address: receiver,
		Satoshi: bitcoin.ParseSatoshi(req.Amount.String()),
	}}
	mainInputs, feeInputs, err := node.store.ListAllBitcoinUTXOsForHolder(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ListAllBitcoinUTXOsForHolder(%s) => %v", req.Holder, err)
	}
	psbt, err := bitcoin.BuildPartiallySignedTransaction(mainInputs, feeInputs, outputs, int64(info.Fee), req.Operation().IdBytes(), safe.Chain)
	logger.Printf("bitcoin.BuildPartiallySignedTransaction(%v) => %v %v", req, psbt, err)
	if bitcoin.IsInsufficientInputError(err) {
		return node.refundAndFailRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}
	if err != nil {
		return fmt.Errorf("bitcoin.BuildPartiallySignedTransaction(%v) => %v", req, err)
	}
	fee := decimal.New(psbt.Fee, -bitcoin.ValuePrecision)
	if balance.Sub(fee).IsNegative() {
		return node.refundAndFailRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}

	extra = psbt.Marshal()
	exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(extra)))
	typ := byte(common.ActionBitcoinSafeProposeTransaction)
	crv := bitcoinChainCurve(safe.Chain)
	err = node.sendObserverResponseWithReferences(ctx, req.Id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverRespons(%s, %x) => %v", req.Id, exk, err)
	}

	spend := decimal.Zero
	for _, out := range feeInputs {
		amt := decimal.New(out.Satoshi, -bitcoin.ValuePrecision)
		spend = spend.Add(amt)
	}

	data, err := json.Marshal([]map[string]string{
		{"receiver": receiver, "amount": req.Amount.String()},
	})
	if err != nil {
		panic(err)
	}
	tx := &store.Transaction{
		TransactionHash: psbt.Hash,
		RawTransaction:  hex.EncodeToString(extra),
		Holder:          req.Holder,
		Chain:           safe.Chain,
		State:           common.RequestStateInitial,
		Data:            string(data),
		Fee:             fee,
		RequestId:       req.Id,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	return node.store.WriteTransactionWithRequest(ctx, tx, append(mainInputs, feeInputs...), spend)
}

func (node *Node) processBitcoinSafeRevokeTransaction(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	chain := bitcoinCurveChain(req.Curve)
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	}
	if safe == nil || safe.Chain != chain {
		return node.store.FailRequest(ctx, req.Id)
	}

	assetId := SafeBitcoinChainId
	switch safe.Chain {
	case SafeChainBitcoin:
	case SafeChainLitecoin:
		assetId = SafeLitecoinChainId
	default:
		panic(safe.Chain)
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

	msg := bitcoin.HashMessageForSignature(tx.TransactionHash, safe.Chain)
	err = bitcoin.VerifySignatureDER(req.Holder, msg, extra[16:])
	logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", req, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	bondId, _, err := node.getBondAsset(ctx, assetId, safe.Holder)
	logger.Printf("node.getBondAsset(%s, %s) => %s %v", assetId, req.Holder, bondId, err)
	if err != nil {
		return fmt.Errorf("node.getBondAsset(%s, %s) => %v", assetId, req.Holder, err)
	}
	var transfers []map[string]string
	err = json.Unmarshal([]byte(tx.Data), &transfers)
	if err != nil {
		panic(err)
	}
	amount := decimal.Zero
	for _, t := range transfers {
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

func (node *Node) processBitcoinSafeApproveTransaction(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	chain := bitcoinCurveChain(req.Curve)
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
	}

	msg := bitcoin.HashMessageForSignature(tx.TransactionHash, safe.Chain)
	err = bitcoin.VerifySignatureDER(req.Holder, msg, extra[16:])
	logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", req, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	b := common.DecodeHexOrPanic(tx.RawTransaction)
	psbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)
	msgTx := psbt.Packet.UnsignedTx
	if len(psbt.Packet.Unknowns[0].Value) != 32*len(msgTx.TxIn) {
		panic(len(psbt.Packet.Unknowns[0].Value))
	}

	var requests []*store.SignatureRequest
	for idx := range msgTx.TxIn {
		pop := msgTx.TxIn[idx].PreviousOutPoint
		required := node.checkBitcoinUTXOSignatureRequired(ctx, pop)
		logger.Printf("node.checkBitcoinUTXOSignatureRequired(%s, %d) => %t", pop.Hash.String(), pop.Index, required)
		if !required {
			continue
		}
		pending, err := node.checkBitcoinUTXOSignaturePending(ctx, tx.TransactionHash, idx, req)
		logger.Printf("node.checkBitcoinUTXOSignaturePending(%s, %d) => %t %v", tx.TransactionHash, idx, pending, err)
		if err != nil {
			return err
		} else if pending {
			continue
		}

		hash := psbt.SigHash(idx)
		sr := &store.SignatureRequest{
			TransactionHash: tx.TransactionHash,
			InputIndex:      idx,
			Signer:          safe.Signer,
			Curve:           req.Curve,
			Message:         hex.EncodeToString(hash),
			State:           common.RequestStateInitial,
			CreatedAt:       req.CreatedAt,
			UpdatedAt:       req.CreatedAt,
		}
		sr.RequestId = mixin.UniqueConversationID(req.Id, sr.Message)
		requests = append(requests, sr)
	}
	err = node.store.WriteSignatureRequestsWithRequest(ctx, requests, tx.TransactionHash, req)
	logger.Printf("store.WriteSignatureRequestsWithRequest(%s, %d) => %v", tx.TransactionHash, len(requests), err)
	if err != nil {
		return fmt.Errorf("store.WriteSignatureRequestsWithRequest(%s) => %v", tx.TransactionHash, err)
	}

	for _, sr := range requests {
		err := node.sendSignerSignRequest(ctx, sr)
		if err != nil {
			return fmt.Errorf("node.sendSignerSignRequest(%v) => %v", sr, err)
		}
	}
	return nil
}

func (node *Node) processBitcoinSafeSignatureResponse(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleSigner {
		panic(req.Role)
	}
	old, err := node.store.ReadSignatureRequest(ctx, req.Id)
	logger.Printf("store.ReadSignatureRequest(%s) => %v %v", req.Id, old, err)
	if err != nil {
		return fmt.Errorf("store.ReadSignatureRequest(%s) => %v", req.Id, err)
	}
	if old == nil || old.State == common.RequestStateDone || old.CreatedAt.Add(SafeSignatureTimeout).Before(req.CreatedAt) {
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

	sig, _ := hex.DecodeString(req.Extra)
	msg := common.DecodeHexOrPanic(old.Message)
	err = bitcoin.VerifySignatureDER(safe.Signer, msg, sig)
	logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", req, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	err = node.store.FinishSignatureRequest(ctx, req)
	logger.Printf("store.FinishSignatureRequest(%s) => %v", req.Id, err)
	if err != nil {
		return fmt.Errorf("store.FinishSignatureRequest(%s) => %v", req.Id, err)
	}

	b := common.DecodeHexOrPanic(tx.RawTransaction)
	spsbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)
	msgTx := spsbt.Packet.UnsignedTx

	requests, err := node.store.ListAllSignaturesForTransaction(ctx, old.TransactionHash, common.RequestStatePending)
	logger.Printf("store.ListAllSignaturesForTransaction(%s) => %d %v", old.TransactionHash, len(requests), err)
	if err != nil {
		return fmt.Errorf("store.ListAllSignaturesForTransaction(%s) => %v", old.TransactionHash, err)
	}

	for idx := range msgTx.TxIn {
		pop := msgTx.TxIn[idx].PreviousOutPoint
		required := node.checkBitcoinUTXOSignatureRequired(ctx, pop)
		if !required {
			continue
		}

		sr := requests[idx]
		if sr == nil {
			return node.store.FailRequest(ctx, req.Id)
		}
		hash := spsbt.SigHash(idx)
		msg := common.DecodeHexOrPanic(sr.Message)
		if !bytes.Equal(hash, msg) {
			panic(sr.Message)
		}
		sig := common.DecodeHexOrPanic(sr.Signature.String)
		err = bitcoin.VerifySignatureDER(safe.Signer, hash, sig)
		if err != nil {
			panic(sr.Signature.String)
		}
		spsbt.Packet.Inputs[idx].PartialSigs = []*psbt.PartialSig{{
			PubKey:    common.DecodeHexOrPanic(safe.Signer),
			Signature: sig,
		}}
	}

	exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(spsbt.Marshal())))
	id := mixin.UniqueConversationID(old.TransactionHash, hex.EncodeToString(exk[:]))
	typ := byte(common.ActionBitcoinSafeApproveTransaction)
	crv := bitcoinChainCurve(safe.Chain)
	err = node.sendObserverResponseWithReferences(ctx, id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", id, exk, err)
	}
	raw := hex.EncodeToString(spsbt.Marshal())
	return node.store.FinishTransactionSignaturesWithRequest(ctx, old.TransactionHash, raw, req, int64(len(msgTx.TxIn)))
}

func (node *Node) checkBitcoinUTXOSignaturePending(ctx context.Context, hash string, index int, req *common.Request) (bool, error) {
	old, err := node.store.ReadSignatureRequestByTransactionIndex(ctx, hash, index)
	if err != nil {
		return false, err
	}
	if old == nil {
		return false, nil
	}
	if old.State != common.RequestStateInitial {
		return true, nil
	}
	return old.CreatedAt.Add(SafeSignatureTimeout).After(req.CreatedAt), nil
}

func (node *Node) checkBitcoinUTXOSignatureRequired(ctx context.Context, pop wire.OutPoint) bool {
	utxo, _ := node.store.ReadBitcoinUTXO(ctx, pop.Hash.String(), int(pop.Index))
	return bitcoin.CheckMultisigHolderSignerScript(utxo.Script)
}

func (node *Node) bitcoinTimeLockDuration(ctx context.Context) time.Duration {
	if common.CheckTestEnvironment(ctx) {
		return bitcoin.TimeLockMinimum
	}
	dur := time.Hour * 24 * time.Duration(node.conf.RecoveryDurationDays)
	if dur < bitcoin.TimeLockMinimum || dur > bitcoin.TimeLockMaximum {
		return bitcoin.TimeLockMaximum
	}
	return dur
}
