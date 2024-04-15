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
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

// This will close the account and move all funds to recovery address.
// For Ethereum, the smart contract account should have a function to move
// all assets to the recovery address, and the safe asset here used is safeETH.
// For Mixin, just accepts safeXIN and build many transactions for all assets.
// For Ethereum or Mixin, it's mandatory to have some minimum ETH or XIN
// in the account for it to be active.
//
// Recovery Processes With Holder Key:
// 1 account holder build transaction raw and sign, POST /accounts/:id with action 'close' to submit recovery request
// 2 account observer sign transaction raw of holder signed recovery transaction, POST /recoveries/:address (the address of account)
// 3 transfer fee to Safe Observer Node to activate recovery
// Recovery Processes Without Holder Key:
// 1 propose recovery tx
// 2 POST /accounts/:id with action 'close' to submit recovery request
// 3 account observer sign transaction raw of holder signed recovery transaction, POST /recoveries/:address (the address of account)
// 4 transfer fee to Safe Observer Node to activate recovery
func (node *Node) processBitcoinSafeCloseAccount(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	chain := SafeCurveChain(req.Curve)
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	}
	if safe == nil || safe.Chain != chain {
		return node.store.FailRequest(ctx, req.Id)
	}
	switch safe.State {
	case SafeStateApproved, SafeStateClosed:
	default:
		return node.store.FailRequest(ctx, req.Id)
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) != 48 {
		return node.store.FailRequest(ctx, req.Id)
	}
	var ref crypto.Hash
	copy(ref[:], extra[16:])
	raw := node.readStorageExtraFromObserver(ctx, ref)

	opk, err := node.deriveBIP32WithPath(ctx, safe.Observer, common.DecodeHexOrPanic(safe.Path))
	if err != nil {
		return fmt.Errorf("bitcoin.DeriveBIP32(%s) => %v", safe.Observer, err)
	}
	signedByObserver := bitcoin.CheckTransactionPartiallySignedBy(hex.EncodeToString(raw), opk)
	logger.Printf("bitcoin.CheckTransactionPartiallySignedBy(%x, %s) => %t", raw, opk, signedByObserver)
	if !signedByObserver {
		return node.store.FailRequest(ctx, req.Id)
	}
	opsbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(raw)
	if !opsbt.IsRecoveryTransaction() {
		return node.store.FailRequest(ctx, req.Id)
	}
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

	count, err := node.store.CountUnfinishedTransactionsByHolder(ctx, safe.Holder)
	logger.Printf("store.CountUnfinishedTransactionsByHolder(%s) => %d %v", safe.Holder, count, err)
	if err != nil {
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
		if count != 0 {
			return node.store.FailRequest(ctx, req.Id)
		}
		err = node.closeBitcoinAccountWithHolder(ctx, req, safe, raw, mainInputs, receiver)
		logger.Printf("node.closeBitcoinAccountWithHolder(%v, %s) => %v", req, receiver, err)
		return err
	}

	if count != 1 {
		return node.store.FailRequest(ctx, req.Id)
	}
	if len(mainInputs) != 0 {
		return node.store.FailRequest(ctx, req.Id)
	}
	tx, err := node.store.ReadTransactionByRequestId(ctx, rid.String())
	if err != nil {
		return fmt.Errorf("store.ReadTransactionByRequestId(%v) => %s %v", req, rid.String(), err)
	} else if tx == nil {
		return node.store.FailRequest(ctx, req.Id)
	} else if tx.State == common.RequestStateDone {
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
	info, err := node.store.ReadLatestNetworkInfo(ctx, safe.Chain, req.CreatedAt)
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
		if bo.Height == 0 || bo.Height+sequence+100 > info.Height {
			return fmt.Errorf("invalid timelock sequence to close account %d %d", bo.Height, info.Height)
		}
		total = total + bo.Satoshi

		pending, err := node.checkTransactionIndexSignaturePending(ctx, txHash, idx, req)
		logger.Printf("node.checkTransactionIndexSignaturePending(%s, %d) => %t %v", txHash, idx, pending, err)
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
		sr.RequestId = common.UniqueId(req.Id, sr.Message)
		requests = append(requests, sr)
	}
	if total != msgTx.TxOut[0].Value {
		return node.store.FailRequest(ctx, req.Id)
	}
	if safe.State == SafeStateApproved {
		err = node.store.CloseAccountBySignatureRequestsWithRequest(ctx, requests, txHash, req)
		logger.Printf("store.CloseAccountBySignatureRequestsWithRequest(%s, %v, %v) => %v", txHash, len(requests), req, err)
		if err != nil {
			return fmt.Errorf("store.WriteSignatureRequestsWithRequest(%s) => %v", txHash, err)
		}
	} else {
		err = node.store.WriteSignatureRequestsWithRequest(ctx, requests, txHash, req)
		logger.Printf("store.WriteSignatureRequestsWithRequest(%s, %d, %v) => %v", txHash, len(requests), req, err)
		if err != nil {
			return fmt.Errorf("store.WriteSignatureRequestsWithRequest(%s) => %v", txHash, err)
		}
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
	opsbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(raw)
	msgTx := opsbt.UnsignedTx
	txHash := msgTx.TxHash().String()
	signedByHolder := bitcoin.CheckTransactionPartiallySignedBy(hex.EncodeToString(raw), safe.Holder)
	logger.Printf("bitcoin.CheckTransactionPartiallySignedBy(%x, %s) => %t", raw, safe.Holder, signedByHolder)
	if !signedByHolder {
		return node.store.FailRequest(ctx, req.Id)
	}

	amt := decimal.New(msgTx.TxOut[0].Value, -bitcoin.ValuePrecision)
	data := common.MarshalJSONOrPanic([]map[string]string{{
		"receiver": receiver,
		"amount":   amt.String(),
	}})
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

	exk := node.writeStorageUntilSnapshot(ctx, []byte(common.Base91Encode(opsbt.Marshal())))
	id := common.UniqueId(tx.TransactionHash, hex.EncodeToString(exk[:]))
	typ := byte(common.ActionBitcoinSafeApproveTransaction)
	crv := SafeChainCurve(safe.Chain)
	err := node.sendObserverResponseWithReferences(ctx, id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", id, exk, err)
	}

	transacionInputs := store.TransactionInputsFromBitcoin(mainInputs)
	return node.store.CloseAccountByTransactionWithRequest(ctx, tx, transacionInputs, common.RequestStateDone)
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
	path := bitcoinDefaultDerivationPath()

	wsa, err := node.buildBitcoinWitnessAccountWithDerivation(ctx, req.Holder, signer, observer, path, arp.Timelock, chain)
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
	exk := node.writeStorageUntilSnapshot(ctx, []byte(common.Base91Encode(extra)))
	typ := byte(common.ActionBitcoinSafeProposeAccount)
	crv := SafeChainCurve(chain)
	err = node.sendObserverResponseWithReferences(ctx, req.Id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", req.Id, exk, err)
	}

	sp := &store.SafeProposal{
		RequestId: req.Id,
		Chain:     chain,
		Holder:    req.Holder,
		Signer:    signer,
		Observer:  observer,
		Timelock:  arp.Timelock,
		Path:      hex.EncodeToString(path),
		Address:   wsa.Address,
		Extra:     extra,
		Receivers: arp.Receivers,
		Threshold: arp.Threshold,
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
	chain := SafeCurveChain(req.Curve)

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
	exk := node.writeStorageUntilSnapshot(ctx, []byte(common.Base91Encode(sp.Extra)))
	typ := byte(common.ActionBitcoinSafeApproveAccount)
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
	chain := SafeCurveChain(req.Curve)
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
	if err != nil || deployed.Sign() <= 0 {
		return fmt.Errorf("api.CheckFatoryAssetDeployed(%s) => %v", meta.AssetKey, err)
	}
	id := uuid.Must(uuid.FromBytes(deployed.Bytes()))
	if id.String() != assetId {
		return node.store.FailRequest(ctx, req.Id)
	}

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

	bondId, _, err := node.getBondAsset(ctx, id.String(), req.Holder)
	logger.Printf("node.getBondAsset(%s, %s) => %s %v", id.String(), req.Holder, bondId, err)
	if err != nil {
		return fmt.Errorf("node.getBondAsset(%s, %s) => %v", id.String(), req.Holder, err)
	}
	if crypto.Sha256Hash([]byte(req.AssetId)) != bondId {
		return node.store.FailRequest(ctx, req.Id)
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) < 33 {
		return node.store.FailRequest(ctx, req.Id)
	}

	mainInputs, err := node.store.ListAllBitcoinUTXOsForHolder(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ListAllBitcoinUTXOsForHolder(%s) => %v", req.Holder, err)
	}
	switch extra[0] {
	case common.FlagProposeNormalTransaction:
	case common.FlagProposeRecoveryTransaction:
		for _, input := range mainInputs {
			input.RouteBackup = true
		}
	default:
		return node.store.FailRequest(ctx, req.Id)
	}
	extra = extra[1:]

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

	psbt, err := bitcoin.BuildPartiallySignedTransaction(mainInputs, outputs, req.Operation().IdBytes(), safe.Chain)
	logger.Printf("bitcoin.BuildPartiallySignedTransaction(%v) => %v %v", req, psbt, err)
	if bitcoin.IsInsufficientInputError(err) {
		return node.refundAndFailRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}
	if err != nil {
		return fmt.Errorf("bitcoin.BuildPartiallySignedTransaction(%v) => %v", req, err)
	}

	extra = psbt.Marshal()
	exk := node.writeStorageUntilSnapshot(ctx, []byte(common.Base91Encode(extra)))
	typ := byte(common.ActionBitcoinSafeProposeTransaction)
	crv := SafeChainCurve(safe.Chain)
	err = node.sendObserverResponseWithReferences(ctx, req.Id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", req.Id, exk, err)
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
	if len(outputs) > 256 {
		logger.Printf("invalid count of outputs: %d", len(outputs))
		return node.refundAndFailRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}
	if !total.Equal(req.Amount) {
		return node.store.FailRequest(ctx, req.Id)
	}
	data := common.MarshalJSONOrPanic(recipients)
	tx := &store.Transaction{
		TransactionHash: psbt.Hash(),
		RawTransaction:  hex.EncodeToString(extra),
		Holder:          req.Holder,
		Chain:           safe.Chain,
		AssetId:         assetId,
		State:           common.RequestStateInitial,
		Data:            string(data),
		RequestId:       req.Id,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	transacionInputs := store.TransactionInputsFromBitcoin(mainInputs)
	return node.store.WriteTransactionWithRequest(ctx, tx, transacionInputs)
}

func (node *Node) processBitcoinSafeApproveTransaction(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	chain := SafeCurveChain(req.Curve)
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
	} else if tx.State == common.RequestStateDone {
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

		pending, err := node.checkTransactionIndexSignaturePending(ctx, tx.TransactionHash, idx, req)
		logger.Printf("node.checkTransactionIndexSignaturePending(%s, %d) => %t %v", tx.TransactionHash, idx, pending, err)
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

func (node *Node) processBitcoinSafeSignatureResponse(ctx context.Context, req *common.Request, safe *store.Safe, tx *store.Transaction, old *store.SignatureRequest) error {
	if req.Role != common.RequestRoleSigner {
		panic(req.Role)
	}

	spk, err := node.deriveBIP32WithPath(ctx, safe.Signer, common.DecodeHexOrPanic(safe.Path))
	if err != nil {
		return fmt.Errorf("node.deriveBIP32WithPath(%s, %s) => %v", safe.Signer, safe.Path, err)
	}
	sig, _ := hex.DecodeString(req.Extra)
	msg := common.DecodeHexOrPanic(old.Message)
	err = bitcoin.VerifySignatureDER(spk, msg, sig)
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
		err = bitcoin.VerifySignatureDER(spk, msg, sig)
		if err != nil {
			panic(sr.Signature.String)
		}
		spsbt.Inputs[idx].PartialSigs = []*psbt.PartialSig{{
			PubKey:    common.DecodeHexOrPanic(spk),
			Signature: sig,
		}}
	}

	exk := node.writeStorageUntilSnapshot(ctx, []byte(common.Base91Encode(spsbt.Marshal())))
	id := common.UniqueId(old.TransactionHash, hex.EncodeToString(exk[:]))
	typ := byte(common.ActionBitcoinSafeApproveTransaction)
	crv := SafeChainCurve(safe.Chain)
	err = node.sendObserverResponseWithReferences(ctx, id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", id, exk, err)
	}
	raw := hex.EncodeToString(spsbt.Marshal())
	err = node.store.FinishTransactionSignaturesWithRequest(ctx, old.TransactionHash, raw, req, int64(len(msgTx.TxIn)), safe)
	logger.Printf("store.FinishTransactionSignaturesWithRequest(%s, %s, %v) => %v", old.TransactionHash, raw, req, err)
	return err
}

func (node *Node) buildBitcoinWitnessAccountWithDerivation(ctx context.Context, holder, signer, observer string, path []byte, timelock time.Duration, chain byte) (*bitcoin.WitnessScriptAccount, error) {
	sdk, err := node.deriveBIP32WithPath(ctx, signer, path)
	logger.Verbosef("bitcoin.DeriveBIP32(%s) => %s %v", signer, sdk, err)
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

func (node *Node) checkTransactionIndexSignaturePending(ctx context.Context, hash string, index int, req *common.Request) (bool, error) {
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
