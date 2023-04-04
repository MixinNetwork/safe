package keeper

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/domains/mvm"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/btcsuite/btcd/wire"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid"
	"github.com/shopspring/decimal"
)

const (
	SafeChainBitcoin  = 1
	SafeChainEthereum = 2
	SafeChainMixin    = 3
	SafeChainMVM      = 4

	SafeBitcoinChainId  = "c6d0c728-2624-429b-8e0d-d9d19b6592fa"
	SafeEthereumChainId = "43d61dcd-e413-450d-80b8-101d5e903357"
	SafeMVMChainId      = "a0ffd769-5850-4b48-9651-d2ae44a3e64d"

	SafeNetworkInfoTimeout = 3 * time.Minute
	SafeSignatureTimeout   = 10 * time.Minute
)

func (node *Node) processBitcoinSafeProposeAccount(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleHolder {
		panic(req.Role)
	}
	receivers, threshold, err := req.ParseMixinRecipient()
	logger.Printf("req.ParseMixinRecipient(%v) => %v %d %v", req, receivers, threshold, err)
	if err != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}

	plan, err := node.store.ReadAccountPlan(ctx, SafeChainBitcoin)
	logger.Printf("store.ReadAccountPlan(%d) => %v %v", SafeChainBitcoin, plan, err)
	if err != nil {
		return fmt.Errorf("node.ReadAccountPrice(%d) => %v", SafeChainBitcoin, err)
	} else if plan == nil || !plan.AccountPriceAmount.IsPositive() {
		return node.refundAndFinishRequest(ctx, req, receivers, int(threshold))
	}
	if req.AssetId != plan.AccountPriceAsset {
		return node.store.FinishRequest(ctx, req.Id)
	}
	if req.Amount.Cmp(plan.AccountPriceAmount) < 0 {
		return node.store.FinishRequest(ctx, req.Id)
	}
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	} else if safe != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}
	old, err := node.store.ReadSafeProposal(ctx, req.Id)
	if err != nil {
		return fmt.Errorf("store.ReadSafeProposal(%s) => %v", req.Id, err)
	} else if old != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}

	signer, observer, accountant, err := node.store.AssignSignerAndObserverToHolder(ctx, req)
	logger.Printf("store.AssignSignerAndObserverToHolder(%s) => %s %s %s %v", req.Holder, signer, observer, accountant, err)
	if err != nil {
		return fmt.Errorf("store.AssignSignerAndObserverToHolder(%v) => %v", req, err)
	}
	if signer == "" || observer == "" || accountant == "" {
		return node.refundAndFinishRequest(ctx, req, receivers, int(threshold))
	}
	if !common.CheckUnique(req.Holder, signer, observer, accountant) {
		return node.refundAndFinishRequest(ctx, req, receivers, int(threshold))
	}
	timelock := bitcoinTimeLockDuration(ctx)
	wsa, err := bitcoin.BuildWitnessScriptAccount(req.Holder, signer, observer, timelock)
	if err != nil {
		return fmt.Errorf("bitcoin.BuildWitnessScriptAccount(%s, %s, %s) => %v", req.Holder, signer, observer, err)
	}
	awka, err := bitcoin.BuildWitnessKeyAccount(accountant)
	if err != nil {
		return fmt.Errorf("bitcoin.BuildWitnessKeyAccount(%s) => %v", accountant, err)
	}

	old, err = node.store.ReadSafeProposalByAddress(ctx, wsa.Address)
	if err != nil {
		return fmt.Errorf("store.ReadSafeProposalByAddress(%s) => %v", wsa.Address, err)
	} else if old != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}

	extra := wsa.MarshalWithAccountant(awka.Address)
	exk := node.writeToMVMOrPanic(ctx, extra)
	if !bytes.Equal(exk, common.MVMHash(extra)) {
		panic(hex.EncodeToString(extra))
	}
	err = node.sendObserverResponse(ctx, req.Id, common.ActionBitcoinSafeProposeAccount, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverRespons(%s, %x) => %v", req.Id, exk, err)
	}

	sp := &store.SafeProposal{
		RequestId:  req.Id,
		Chain:      SafeChainBitcoin,
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
		return node.store.FinishRequest(ctx, req.Id)
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) < 64 {
		return node.store.FinishRequest(ctx, req.Id)
	}
	rid, err := uuid.FromBytes(extra[:16])
	if err != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}
	sp, err := node.store.ReadSafeProposal(ctx, rid.String())
	if err != nil {
		return fmt.Errorf("store.ReadSafeProposal(%v) => %s %v", req, rid.String(), err)
	} else if sp == nil {
		return node.store.FinishRequest(ctx, req.Id)
	} else if sp.Holder != req.Holder {
		return node.store.FinishRequest(ctx, req.Id)
	} else if sp.Chain != SafeChainBitcoin {
		return node.store.FinishRequest(ctx, req.Id)
	}

	msg := bitcoin.HashMessageForSignature(sp.Address)
	err = bitcoin.VerifySignatureDER(req.Holder, msg, extra[16:])
	logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", req, err)
	if err != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}
	awka, err := bitcoin.BuildWitnessKeyAccount(sp.Accountant)
	if err != nil {
		return fmt.Errorf("bitcoin.BuildWitnessKeyAccount(%s) => %v", sp.Accountant, err)
	}

	spr, err := node.store.ReadRequest(ctx, sp.RequestId)
	if err != nil {
		return fmt.Errorf("store.ReadRequest(%s) => %v", sp.RequestId, err)
	}
	exk := common.MVMHash(sp.Extra)
	err = node.sendObserverResponseWithAsset(ctx, req.Id, common.ActionBitcoinSafeApproveAccount, exk, spr.AssetId, spr.Amount.String())
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
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	}
	if safe == nil || safe.Chain != SafeChainBitcoin {
		return node.store.FinishRequest(ctx, req.Id)
	}

	meta, err := node.fetchAssetMeta(ctx, req.AssetId)
	logger.Printf("node.fetchAssetMeta(%s) => %v %v", req.AssetId, meta, err)
	if err != nil {
		return fmt.Errorf("node.fetchAssetMeta(%s) => %v", req.AssetId, err)
	}
	if meta.Chain != SafeChainMVM {
		return node.store.FinishRequest(ctx, req.Id)
	}
	deployed, err := abi.CheckFactoryAssetDeployed(node.conf.MVMRPC, meta.AssetKey)
	logger.Printf("abi.CheckFactoryAssetDeployed(%s) => %v %v", meta.AssetKey, deployed, err)
	if err != nil {
		return fmt.Errorf("api.CheckFatoryAssetDeployed(%s) => %v", meta.AssetKey, err)
	}
	if deployed.Sign() <= 0 {
		return node.store.FinishRequest(ctx, req.Id)
	}
	id := uuid.Must(uuid.FromBytes(deployed.Bytes()))
	if id.String() != SafeBitcoinChainId {
		return node.store.FinishRequest(ctx, req.Id)
	}

	plan, err := node.store.ReadAccountPlan(ctx, safe.Chain)
	logger.Printf("store.ReadAccountPlan(%d) => %v %v", safe.Chain, plan, err)
	if err != nil {
		return fmt.Errorf("store.ReadAccountPlan(%d) => %v", safe.Chain, err)
	} else if plan == nil || !plan.TransactionMinimum.IsPositive() {
		return node.refundAndFinishRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}
	if req.Amount.Cmp(plan.TransactionMinimum) < 0 {
		return node.store.FinishRequest(ctx, req.Id)
	}

	bondId, _, err := node.getBondAsset(ctx, id.String(), req.Holder)
	logger.Printf("node.getBondAsset(%s, %s) => %s %v", id.String(), req.Holder, bondId, err)
	if err != nil {
		return fmt.Errorf("node.getBondAsset(%s, %s) => %v", id.String(), req.Holder, err)
	}
	if crypto.NewHash([]byte(req.AssetId)) != bondId {
		return node.store.FinishRequest(ctx, req.Id)
	}

	balance, err := node.store.ReadAccountantBalance(ctx, req.Holder)
	logger.Printf("node.ReadAccountantBalance(%v) => %v %v", req.Holder, balance, err)
	if err != nil {
		return fmt.Errorf("store.ReadAccountantBalance(%s) => %v", req.Holder, err)
	}
	if balance.IsZero() {
		return node.refundAndFinishRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) < 32 {
		return node.store.FinishRequest(ctx, req.Id)
	}
	iid, err := uuid.FromBytes(extra[:16])
	if err != nil || iid.String() == uuid.Nil.String() {
		return node.store.FinishRequest(ctx, req.Id)
	}
	receiver, err := bitcoin.ParseAddress(string(extra[16:]))
	logger.Printf("bitcoin.ParseAddress(%s) => %s %v", string(extra), receiver, err)
	if err != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}
	info, err := node.store.ReadNetworkInfo(ctx, iid.String())
	logger.Printf("store.ReadNetworkInfo(%s) => %v %v", iid.String(), info, err)
	if err != nil {
		return fmt.Errorf("store.ReadNetworkInfo(%s) => %v", iid.String(), err)
	}
	if info == nil || info.Chain != safe.Chain {
		return node.store.FinishRequest(ctx, req.Id)
	}
	if info.CreatedAt.Add(SafeNetworkInfoTimeout * 30).Before(req.CreatedAt) {
		return node.refundAndFinishRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}

	outputs := []*bitcoin.Output{{
		Address: receiver,
		Satoshi: bitcoin.ParseSatoshi(req.Amount.String()),
	}}
	mainInputs, feeInputs, err := node.store.ListAllBitcoinUTXOsForHolder(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ListAllBitcoinUTXOsForHolder(%s) => %v", req.Holder, err)
	}
	psbt, err := bitcoin.BuildPartiallySignedTransaction(mainInputs, feeInputs, outputs, int64(info.Fee), req.Operation().IdBytes())
	logger.Printf("bitcoin.BuildPartiallySignedTransaction(%v) => %v %v", req, psbt, err)
	if bitcoin.IsInsufficientInputError(err) {
		return node.refundAndFinishRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}
	if err != nil {
		return fmt.Errorf("bitcoin.BuildPartiallySignedTransaction(%v) => %v", req, err)
	}
	fee := decimal.New(psbt.Fee, -bitcoin.ValuePrecision)
	if balance.Sub(fee).IsNegative() {
		return node.refundAndFinishRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}

	extra = psbt.Marshal()
	exk := node.writeToMVMOrPanic(ctx, extra)
	err = node.sendObserverResponse(ctx, req.Id, common.ActionBitcoinSafeProposeTransaction, exk)
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
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	}
	if safe == nil || safe.Chain != SafeChainBitcoin {
		return node.store.FinishRequest(ctx, req.Id)
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) < 64 {
		return node.store.FinishRequest(ctx, req.Id)
	}
	rid, err := uuid.FromBytes(extra[:16])
	if err != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}
	tx, err := node.store.ReadTransactionByRequestId(ctx, rid.String())
	if err != nil {
		return fmt.Errorf("store.ReadTransactionByRequestId(%v) => %s %v", req, rid.String(), err)
	} else if tx == nil {
		return node.store.FinishRequest(ctx, req.Id)
	} else if tx.Holder != req.Holder {
		return node.store.FinishRequest(ctx, req.Id)
	} else if tx.State != common.RequestStateInitial {
		return node.store.FinishRequest(ctx, req.Id)
	}

	msg := bitcoin.HashMessageForSignature(tx.TransactionHash)
	err = bitcoin.VerifySignatureDER(req.Holder, msg, extra[16:])
	logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", req, err)
	if err != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}

	bondId, _, err := node.getBondAsset(ctx, SafeBitcoinChainId, safe.Holder)
	logger.Printf("node.getBondAsset(%s, %s) => %s %v", SafeBitcoinChainId, req.Holder, bondId, err)
	if err != nil {
		return fmt.Errorf("node.getBondAsset(%s, %s) => %v", SafeBitcoinChainId, req.Holder, err)
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
		return node.store.FinishRequest(ctx, req.Id)
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
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	}
	if safe == nil || safe.Chain != SafeChainBitcoin {
		return node.store.FinishRequest(ctx, req.Id)
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) < 64 {
		return node.store.FinishRequest(ctx, req.Id)
	}
	rid, err := uuid.FromBytes(extra[:16])
	if err != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}
	tx, err := node.store.ReadTransactionByRequestId(ctx, rid.String())
	if err != nil {
		return fmt.Errorf("store.ReadTransactionByRequestId(%v) => %s %v", req, rid.String(), err)
	} else if tx == nil {
		return node.store.FinishRequest(ctx, req.Id)
	} else if tx.Holder != req.Holder {
		return node.store.FinishRequest(ctx, req.Id)
	}

	msg := bitcoin.HashMessageForSignature(tx.TransactionHash)
	err = bitcoin.VerifySignatureDER(req.Holder, msg, extra[16:])
	logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", req, err)
	if err != nil {
		return node.store.FinishRequest(ctx, req.Id)
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

func (node *Node) refundAndFinishRequest(ctx context.Context, req *common.Request, receivers []string, threshold int) error {
	err := node.buildTransaction(ctx, req.AssetId, receivers, threshold, req.Amount.String(), nil, req.Id)
	if err != nil {
		return err
	}
	return node.store.FinishRequest(ctx, req.Id)
}

func (node *Node) bondMaxSupply(ctx context.Context, chain byte, assetId string) decimal.Decimal {
	switch assetId {
	case SafeBitcoinChainId:
		return decimal.RequireFromString("115792089237316195423570985008687907853269984665640564039457.58400791")
	default:
		panic(assetId)
	}
}

func (node *Node) getBondAsset(ctx context.Context, assetId, holder string) (crypto.Hash, byte, error) {
	asset, err := node.fetchAssetMeta(ctx, assetId)
	if err != nil {
		return crypto.Hash{}, 0, err
	}
	addr := abi.GetFactoryAssetAddress(assetId, asset.Symbol, asset.Name, holder)
	assetKey := strings.ToLower(addr.String())
	err = mvm.VerifyAssetKey(assetKey)
	if err != nil {
		return crypto.Hash{}, 0, err
	}
	return mvm.GenerateAssetId(assetKey), SafeChainMVM, nil
}

func bitcoinTimeLockDuration(ctx context.Context) time.Duration {
	if common.CheckTestEnvironment(ctx) {
		return bitcoin.TimeLockMinimum
	}
	return bitcoin.TimeLockMaximum
}
