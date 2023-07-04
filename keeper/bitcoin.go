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

// This will close the account and move all funds to recovery address.
// For Ethereum, the smart contract account should have a function to move
// all assets to the recovery address, and the safe asset here used is safeETH.
// For Mixin, just accepts safeXIN and build many transactions for all assets.
// For Ethereum or Mixin, it's mandatory to have some minimum ETH or XIN
// in the account for it to be active.
func (node *Node) processBitcoinSafeCloseAccount(ctx context.Context, req *common.Request) error {
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
	if safe.State != SafeStateApproved {
		return node.store.FailRequest(ctx, req.Id)
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) != 48 {
		return node.store.FailRequest(ctx, req.Id)
	}
	var ref crypto.Hash
	copy(ref[:], extra[16:])
	raw := node.readStorageExtraFromObserver(ctx, ref)
	signedByObserver := bitcoin.CheckTransactionPartiallySignedBy(hex.EncodeToString(raw), safe.Observer)
	logger.Printf("bitcoin.CheckTransactionPartiallySignedBy(%x, %s) => %t", raw, safe.Observer, signedByObserver)
	if !signedByObserver {
		return node.store.FailRequest(ctx, req.Id)
	}
	opsbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(raw)
	msgTx := opsbt.UnsignedTx
	txHash := msgTx.TxHash().String()

	if len(msgTx.TxOut) != 2 || msgTx.TxOut[1].Value != 0 {
		return node.store.FailRequest(ctx, req.Id)
	}
	receiver, err := bitcoin.ExtractPkScriptAddr(msgTx.TxOut[0].PkScript, safe.Chain)
	logger.Printf("bitcoin.ExtractPkScriptAddr(%x) => %s %v", msgTx.TxOut[0].PkScript, receiver, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	if receiver == safe.Address {
		return node.store.FailRequest(ctx, req.Id)
	}

	mainInputs, err := node.store.ListAllBitcoinUTXOsForHolder(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ListAllBitcoinUTXOsForHolder(%s) => %v", req.Holder, err)
	}
	rid, err := uuid.FromBytes(extra[:16])
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	if rid.String() == uuid.Nil.String() {
		err = node.closeBitcoinAccountWithHolder(ctx, req, safe, raw, mainInputs, receiver)
		logger.Printf("node.closeBitcoinAccountWithHolder(%v, %s) => %v", req, receiver, err)
		return err
	}

	if len(mainInputs) != 0 {
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
	b := common.DecodeHexOrPanic(tx.RawTransaction)
	psbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)
	if msgTx.TxHash() != psbt.UnsignedTx.TxHash() {
		return node.store.FailRequest(ctx, req.Id)
	}

	rpc, _ := node.bitcoinParams(safe.Chain)
	info, err := node.store.ReadLatestNetworkInfo(ctx, safe.Chain)
	logger.Printf("store.ReadLatestNetworkInfo(%d) => %v %v", safe.Chain, info, err)
	if err != nil {
		return err
	}
	if info == nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	sequence := uint64(bitcoin.ParseSequence(safe.Timelock, safe.Chain))

	var total int64
	var requests []*store.SignatureRequest
	for idx := range msgTx.TxIn {
		pop := msgTx.TxIn[idx].PreviousOutPoint
		required := node.checkBitcoinUTXOSignatureRequired(ctx, pop)
		logger.Printf("node.checkBitcoinUTXOSignatureRequired(%s, %d) => %t", pop.Hash.String(), pop.Index, required)
		if !required {
			continue
		}

		_, bo, err := bitcoin.RPCGetTransactionOutput(safe.Chain, rpc, pop.Hash.String(), int64(pop.Index))
		logger.Printf("bitcoin.RPCGetTransactionOutput(%s, %d) => %v %v", pop.Hash.String(), pop.Index, bo, err)
		if err != nil {
			return err
		}
		if bo.Height > info.Height || bo.Height == 0 {
			return node.store.FailRequest(ctx, req.Id)
		}
		if bo.Height+sequence+100 > info.Height {
			return node.store.FailRequest(ctx, req.Id)
		}
		total = total + bo.Satoshi

		pending, err := node.checkBitcoinUTXOSignaturePending(ctx, txHash, idx, req)
		logger.Printf("node.checkBitcoinUTXOSignaturePending(%s, %d) => %t %v", txHash, idx, pending, err)
		if err != nil {
			return err
		} else if pending {
			continue
		}

		sr := &store.SignatureRequest{
			TransactionHash: txHash,
			InputIndex:      idx,
			Signer:          safe.Signer,
			Curve:           req.Curve,
			Message:         hex.EncodeToString(opsbt.SigHash(idx)),
			State:           common.RequestStateInitial,
			CreatedAt:       req.CreatedAt,
			UpdatedAt:       req.CreatedAt,
		}
		sr.RequestId = mixin.UniqueConversationID(req.Id, sr.Message)
		requests = append(requests, sr)
	}
	if total != msgTx.TxOut[0].Value {
		return node.store.FailRequest(ctx, req.Id)
	}
	err = node.store.CloseAccountBySignatureRequestsWithRequest(ctx, requests, txHash, req)
	logger.Printf("store.CloseAccountBySignatureRequestsWithRequest(%s, %d, %v) => %v", txHash, len(requests), req, err)
	if err != nil {
		return fmt.Errorf("store.WriteSignatureRequestsWithRequest(%s) => %v", txHash, err)
	}

	for _, sr := range requests {
		err := node.sendSignerSignRequest(ctx, sr, safe.Path)
		if err != nil {
			return fmt.Errorf("node.sendSignerSignRequest(%v) => %v", sr, err)
		}
	}
	return nil
}

func (node *Node) closeBitcoinAccountWithHolder(ctx context.Context, req *common.Request, safe *store.Safe, raw []byte, mainInputs []*bitcoin.Input, receiver string) error {
	rpc, _ := node.bitcoinParams(safe.Chain)
	info, err := node.store.ReadLatestNetworkInfo(ctx, safe.Chain)
	logger.Printf("store.ReadLatestNetworkInfo(%d) => %v %v", safe.Chain, info, err)
	if err != nil {
		return err
	}
	if info == nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	opsbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(raw)
	msgTx := opsbt.UnsignedTx
	txHash := msgTx.TxHash().String()
	signedByHolder := bitcoin.CheckTransactionPartiallySignedBy(hex.EncodeToString(raw), safe.Holder)
	logger.Printf("bitcoin.CheckTransactionPartiallySignedBy(%x, %s) => %t", raw, safe.Holder, signedByHolder)
	if !signedByHolder {
		return node.store.FailRequest(ctx, req.Id)
	}
	if ps := msgTx.TxOut[1].PkScript; len(ps) != 18 || uuid.FromBytesOrNil(ps[2:]).String() != req.Id {
		return node.store.FailRequest(ctx, req.Id)
	}

	var total int64
	sequence := uint64(bitcoin.ParseSequence(safe.Timelock, safe.Chain))
	for _, o := range mainInputs {
		_, bo, err := bitcoin.RPCGetTransactionOutput(safe.Chain, rpc, o.TransactionHash, int64(o.Index))
		logger.Printf("bitcoin.RPCGetTransactionOutput(%s, %d) => %v %v", o.TransactionHash, o.Index, bo, err)
		if err != nil {
			return err
		}
		if bo.Height > info.Height || bo.Height == 0 {
			return node.store.FailRequest(ctx, req.Id)
		}
		if bo.Height+sequence+100 > info.Height {
			return node.store.FailRequest(ctx, req.Id)
		}
		total = total + o.Satoshi
	}
	if total != msgTx.TxOut[0].Value {
		return node.store.FailRequest(ctx, req.Id)
	}

	amt := decimal.New(total, -bitcoin.ValuePrecision)
	data, err := json.Marshal([]map[string]string{{
		"receiver": receiver,
		"amount":   amt.String(),
	}})
	if err != nil {
		panic(err)
	}
	tx := &store.Transaction{
		TransactionHash: txHash,
		RawTransaction:  hex.EncodeToString(raw),
		Holder:          req.Holder,
		Chain:           safe.Chain,
		State:           common.RequestStateDone,
		Data:            string(data),
		RequestId:       req.Id,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	return node.store.CloseAccountByTransactionWithRequest(ctx, tx, mainInputs)
}

func (node *Node) processBitcoinSafeProposeAccount(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleHolder {
		panic(req.Role)
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
	timelock, receivers, threshold, err := req.ParseMixinRecipient(rce)
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

	signer, observer, err := node.store.AssignSignerAndObserverToHolder(ctx, req, SafeKeyBackupMaturity)
	logger.Printf("store.AssignSignerAndObserverToHolder(%s) => %s %s %v", req.Holder, signer, observer, err)
	if err != nil {
		return fmt.Errorf("store.AssignSignerAndObserverToHolder(%v) => %v", req, err)
	}
	if signer == "" || observer == "" {
		return node.refundAndFailRequest(ctx, req, receivers, int(threshold))
	}
	if !common.CheckUnique(req.Holder, signer, observer) {
		return node.refundAndFailRequest(ctx, req, receivers, int(threshold))
	}
	path := bitcoinDefaultDerivationPath()

	wsa, err := node.buildBitcoinWitnessAccountWithDerivation(ctx, req.Holder, signer, observer, path, timelock, chain)
	logger.Verbosef("node.buildBitcoinWitnessAccountWithDerivation(%v) => %v %v", req, wsa, err)
	if err != nil {
		return err
	}
	old, err = node.store.ReadSafeProposalByAddress(ctx, wsa.Address)
	if err != nil {
		return fmt.Errorf("store.ReadSafeProposalByAddress(%s) => %v", wsa.Address, err)
	} else if old != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	extra := wsa.Marshal()
	exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(extra)))
	typ := byte(common.ActionBitcoinSafeProposeAccount)
	crv := bitcoinChainCurve(chain)
	err = node.sendObserverResponseWithReferences(ctx, req.Id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverRespons(%s, %x) => %v", req.Id, exk, err)
	}

	sp := &store.SafeProposal{
		RequestId: req.Id,
		Chain:     chain,
		Holder:    req.Holder,
		Signer:    signer,
		Observer:  observer,
		Timelock:  timelock,
		Path:      hex.EncodeToString(path),
		Address:   wsa.Address,
		Extra:     extra,
		Receivers: receivers,
		Threshold: threshold,
		CreatedAt: req.CreatedAt,
		UpdatedAt: req.CreatedAt,
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

	ms := fmt.Sprintf("APPROVE:%s:%s", rid.String(), sp.Address)
	msg := bitcoin.HashMessageForSignature(ms, sp.Chain)
	err = bitcoin.VerifySignatureDER(req.Holder, msg, extra[16:])
	logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", req, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
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
	if safe.State != SafeStateApproved {
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

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) < 32 {
		return node.store.FailRequest(ctx, req.Id)
	}
	iid, err := uuid.FromBytes(extra[:16])
	if err != nil || iid.String() == uuid.Nil.String() {
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

	var outputs []*bitcoin.Output
	ver, _ := common.ReadKernelTransaction(node.conf.MixinRPC, req.MixinHash)
	if len(extra[16:]) == 32 && len(ver.References) == 1 && ver.References[0].String() == hex.EncodeToString(extra[16:]) {
		stx, _ := common.ReadKernelTransaction(node.conf.MixinRPC, ver.References[0])
		extra := common.DecodeMixinObjectExtra(stx.Extra)
		var recipients [][2]string // TODO better encoding
		err = json.Unmarshal(extra, &recipients)
		if err != nil {
			return node.store.FailRequest(ctx, req.Id)
		}
		for _, rp := range recipients {
			script, err := bitcoin.ParseAddress(rp[0], safe.Chain)
			logger.Printf("bitcoin.ParseAddress(%s, %d) => %x %v", string(extra), safe.Chain, script, err)
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
			outputs = append(outputs, &bitcoin.Output{
				Address: rp[0],
				Satoshi: bitcoin.ParseSatoshi(amt.String()),
			})
		}
	} else {
		script, err := bitcoin.ParseAddress(string(extra[16:]), safe.Chain)
		logger.Printf("bitcoin.ParseAddress(%s, %d) => %x %v", string(extra), safe.Chain, script, err)
		if err != nil {
			return node.store.FailRequest(ctx, req.Id)
		}
		outputs = []*bitcoin.Output{{
			Address: string(extra[16:]),
			Satoshi: bitcoin.ParseSatoshi(req.Amount.String()),
		}}
	}

	mainInputs, err := node.store.ListAllBitcoinUTXOsForHolder(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ListAllBitcoinUTXOsForHolder(%s) => %v", req.Holder, err)
	}
	psbt, err := bitcoin.BuildPartiallySignedTransaction(mainInputs, outputs, req.Operation().IdBytes(), safe.Chain)
	logger.Printf("bitcoin.BuildPartiallySignedTransaction(%v) => %v %v", req, psbt, err)
	if bitcoin.IsInsufficientInputError(err) {
		return node.refundAndFailRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}
	if err != nil {
		return fmt.Errorf("bitcoin.BuildPartiallySignedTransaction(%v) => %v", req, err)
	}

	extra = psbt.Marshal()
	exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(extra)))
	typ := byte(common.ActionBitcoinSafeProposeTransaction)
	crv := bitcoinChainCurve(safe.Chain)
	err = node.sendObserverResponseWithReferences(ctx, req.Id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverRespons(%s, %x) => %v", req.Id, exk, err)
	}

	total := decimal.Zero
	recipients := make([]map[string]string, len(outputs))
	for i, out := range outputs {
		amt := decimal.New(out.Satoshi, -bitcoin.ValuePrecision)
		recipients[i] = map[string]string{
			"receiver": out.Address, "amount": amt.String(),
		}
		total = total.Add(amt)
	}
	if !total.Equal(req.Amount) {
		return node.store.FailRequest(ctx, req.Id)
	}
	data, err := json.Marshal(recipients)
	if err != nil {
		panic(err)
	}
	tx := &store.Transaction{
		TransactionHash: psbt.Hash(),
		RawTransaction:  hex.EncodeToString(extra),
		Holder:          req.Holder,
		Chain:           safe.Chain,
		State:           common.RequestStateInitial,
		Data:            string(data),
		RequestId:       req.Id,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	return node.store.WriteTransactionWithRequest(ctx, tx, mainInputs)
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

	ms := fmt.Sprintf("REVOKE:%s:%s", rid.String(), tx.TransactionHash)
	msg := bitcoin.HashMessageForSignature(ms, safe.Chain)
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
	if len(extra) != 48 {
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

	var ref crypto.Hash
	copy(ref[:], extra[16:])
	raw := node.readStorageExtraFromObserver(ctx, ref)
	signed := bitcoin.CheckTransactionPartiallySignedBy(hex.EncodeToString(raw), tx.Holder)
	logger.Printf("bitcoin.CheckTransactionPartiallySignedBy(%x, %s) => %t", raw, tx.Holder, signed)
	if !signed {
		return node.store.FailRequest(ctx, req.Id)
	}
	hpsbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(raw)

	b := common.DecodeHexOrPanic(tx.RawTransaction)
	psbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)
	msgTx := psbt.UnsignedTx
	if msgTx.TxHash() != hpsbt.UnsignedTx.TxHash() {
		return node.store.FailRequest(ctx, req.Id)
	}

	var requests []*store.SignatureRequest
	for idx := range msgTx.TxIn {
		hash := psbt.SigHash(idx)
		pop := msgTx.TxIn[idx].PreviousOutPoint
		if !bytes.Equal(hash, hpsbt.SigHash(idx)) {
			continue
		}

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
	err = node.verifyBitcoinSignatureWithPath(ctx, safe.Signer, safe.Path, msg, sig)
	logger.Printf("node.verifyBitcoinSignatureWithPath(%v) => %v", req, err)
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
	msgTx := spsbt.UnsignedTx

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
		err = node.verifyBitcoinSignatureWithPath(ctx, safe.Signer, safe.Path, hash, sig)
		if err != nil {
			panic(sr.Signature.String)
		}
		spsbt.Inputs[idx].PartialSigs = []*psbt.PartialSig{{
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

func (node *Node) buildBitcoinWitnessAccountWithDerivation(ctx context.Context, holder, signer, observer string, path []byte, timelock time.Duration, chain byte) (*bitcoin.WitnessScriptAccount, error) {
	sdk, err := node.deriveBIP32WithPath(ctx, signer, path)
	logger.Verbosef("bitcoin.DeriveBIP32(%s) => %s %v", observer, sdk, err)
	if err != nil {
		return nil, fmt.Errorf("bitcoin.DeriveBIP32(%s) => %v", signer, err)
	}
	odk, err := node.deriveBIP32WithPath(ctx, observer, path)
	logger.Verbosef("bitcoin.DeriveBIP32(%s) => %s %v", observer, odk, err)
	if err != nil {
		return nil, fmt.Errorf("bitcoin.DeriveBIP32(%s) => %v", observer, err)
	}
	return bitcoin.BuildWitnessScriptAccount(holder, sdk, odk, timelock, chain)
}

func (node *Node) verifyBitcoinSignatureWithPath(ctx context.Context, public, path string, msg, sig []byte) error {
	spk, err := node.deriveBIP32WithPath(ctx, public, common.DecodeHexOrPanic(path))
	if err != nil {
		panic(public)
	}
	return bitcoin.VerifySignatureDER(spk, msg, sig)
}

func (node *Node) deriveBIP32WithPath(ctx context.Context, public string, path8 []byte) (string, error) {
	if path8[0] > 3 {
		panic(path8[0])
	}
	path32 := make([]uint32, path8[0])
	for i := 0; i < int(path8[0]); i++ {
		path32[i] = uint32(path8[1+i])
	}
	sk, err := node.store.ReadKey(ctx, public)
	if err != nil {
		return "", fmt.Errorf("store.ReadKey(%s) => %v", public, err)
	}
	_, sdk, err := bitcoin.DeriveBIP32(public, common.DecodeHexOrPanic(sk.Extra), path32...)
	return sdk, err
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
	utxo, _, _ := node.store.ReadBitcoinUTXO(ctx, pop.Hash.String(), int(pop.Index))
	return bitcoin.CheckMultisigHolderSignerScript(utxo.Script)
}
