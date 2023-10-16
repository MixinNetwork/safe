package keeper

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

func (node *Node) processEthereumSafeCloseAccount(ctx context.Context, req *common.Request) error {
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

	t, err := ethereum.UnmarshalSafeTransaction(raw)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%v) => %v %v", raw, t, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	_, pubs, err := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	logger.Printf("ethereum.GetSortedSafeOwners(%s, %s, %s) => %v, %v", safe.Holder, safe.Signer, safe.Observer, pubs, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	signedByObserver := false
	for i, pub := range pubs {
		if pub == safe.Observer {
			sig := t.Signatures[i]
			err = ethereum.VerifyMessageSignature(safe.Observer, t.Message, sig)
			logger.Printf("ethereum.VerifyMessageSignature(%s %s %s) => %v", safe.Observer, t.Message, sig, err)
			if err == nil {
				signedByObserver = true
			}
		}
	}
	if !signedByObserver {
		return node.store.FailRequest(ctx, req.Id)
	}
	if t.Destination.Hex() == safe.Address {
		return node.store.FailRequest(ctx, req.Id)
	}

	count, err := node.store.CountUnfinishedTransactionsByHolder(ctx, safe.Holder)
	logger.Printf("store.CountUnfinishedTransactionsByHolder(%s) => %d %v", safe.Holder, count, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	rid, err := uuid.FromBytes(extra[:16])
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	if rid.String() == uuid.Nil.String() {
		if count != 0 {
			return node.store.FailRequest(ctx, req.Id)
		}
		err = node.closeEthereumAccountWithHolder(ctx, req, safe, raw, t.Destination.Hex())
		logger.Printf("node.closeEthereumAccountWithHolder(%v, %s) => %v", req, t.Destination.Hex(), err)
		return err
	}

	if count != 1 {
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
	proposedTx, _ := ethereum.UnmarshalSafeTransaction(b)
	if hex.EncodeToString(t.Message) != hex.EncodeToString(proposedTx.Message) {
		logger.Printf("Inconsistent safe tx message: %s %s", hex.EncodeToString(t.Message), hex.EncodeToString(proposedTx.Message))
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
	balance, err := node.store.ReadEthereumBalance(ctx, safe.Address, meta.AssetId)
	logger.Printf("store.ReadEthereumBalance(%s, %s) => %v %v", safe.Address, meta.AssetId, balance, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	if new(big.Int).SetUint64(balance.Balance).Cmp(t.Value) != 0 {
		return fmt.Errorf("Inconsistent safe balance: %d %d", balance.Balance, t.Value.Uint64())
	}

	rpc, _ := node.ethereumParams(safe.Chain)
	info, err := node.store.ReadLatestNetworkInfo(ctx, safe.Chain, req.CreatedAt)
	logger.Printf("store.ReadLatestNetworkInfo(%d) => %v %v", safe.Chain, info, err)
	if err != nil {
		return err
	}
	if info == nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	sequence := uint64(ethereum.ParseSequence(safe.Timelock, safe.Chain))
	transaction, err := ethereum.RPCGetTransactionByHash(rpc, balance.LatestTxHash)
	logger.Printf("ethereum.RPCGetTransactionByHash(%s %s) => %v %v", rpc, balance.LatestTxHash, transaction, err)
	if err != nil {
		return err
	}
	if transaction.BlockHeight == 0 || transaction.BlockHeight+sequence+100 > info.Height {
		return node.store.FailRequest(ctx, req.Id)
	}

	hash, err := ethereum.HashMessageForSignature(hex.EncodeToString(t.Message))
	logger.Printf("ethereum.HashMessageForSignature(%s) => %v %s %v", hex.EncodeToString(t.Message), hash, hex.EncodeToString(hash), err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	sr := &store.SignatureRequest{
		TransactionHash: t.Hash(req.Id),
		InputIndex:      0,
		Signer:          safe.Signer,
		Curve:           req.Curve,
		Message:         hex.EncodeToString(hash),
		State:           common.RequestStateInitial,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	sr.RequestId = common.UniqueId(req.Id, sr.Message)
	err = node.store.CloseAccountBySignatureRequestsWithRequest(ctx, []*store.SignatureRequest{sr}, tx.TransactionHash, req)
	logger.Printf("store.CloseAccountBySignatureRequestsWithRequest(%s, %v, %v) => %v", tx.TransactionHash, sr, req, err)
	if err != nil {
		return fmt.Errorf("store.WriteSignatureRequestsWithRequest(%s) => %v", tx.TransactionHash, err)
	}

	err = node.sendSignerSignRequest(ctx, sr, safe.Path)
	if err != nil {
		return fmt.Errorf("node.sendSignerSignRequest(%v) => %v", sr, err)
	}
	return nil
}

func (node *Node) closeEthereumAccountWithHolder(ctx context.Context, req *common.Request, safe *store.Safe, raw []byte, receiver string) error {
	t, _ := ethereum.UnmarshalSafeTransaction(raw)
	_, pubs, err := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	logger.Printf("ethereum.GetSortedSafeOwners(%s, %s, %s) => %v, %v", safe.Holder, safe.Signer, safe.Observer, pubs, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	signedByHolder := false
	for i, pub := range pubs {
		if pub == safe.Holder {
			sig := t.Signatures[i]
			err = ethereum.VerifyMessageSignature(safe.Holder, t.Message, sig)
			logger.Printf("ethereum.VerifyMessageSignature(%s %s %s) => %v", safe.Holder, t.Message, sig, err)
			if err == nil {
				signedByHolder = true
			}
		}
	}
	if !signedByHolder {
		return node.store.FailRequest(ctx, req.Id)
	}

	amt := decimal.New(t.Value.Int64(), -ethereum.ValuePrecision)
	data := common.MarshalJSONOrPanic([]map[string]string{{
		"receiver": receiver,
		"amount":   amt.String(),
	}})
	tx := &store.Transaction{
		TransactionHash: t.Hash(safe.RequestId),
		RawTransaction:  hex.EncodeToString(raw),
		Holder:          req.Holder,
		Chain:           safe.Chain,
		State:           common.RequestStateDone,
		Data:            string(data),
		RequestId:       req.Id,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	return node.store.CloseAccountByTransactionWithRequest(ctx, tx, nil, common.RequestStateDone)
}

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
	gs, t, err := ethereum.BuildGnosisSafe(ctx, rpc, req.Holder, signer, observer, req.Id, arp.Timelock, chain)
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
		TransactionHash: t.Hash(req.Id),
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

	gs, err := ethereum.UnmarshalGnosisSafe(sp.Extra)
	logger.Printf("ethereum.UnmarshalGnosisSafe(%s) => %v %v", sp.Extra, gs, err)
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

	err = ethereum.VerifyMessageSignature(req.Holder, t.Message, extra[16:])
	logger.Printf("ethereum.VerifyMessageSignature(%v) => %v", req, err)
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
	err = node.store.UpdateInitialTransaction(ctx, tx.TransactionHash, hex.EncodeToString(t.Marshal()))
	logger.Printf("store.UpdateInitialTransaction(%v) => %v", tx, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
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
	err = node.store.WriteUnfinishedSafe(ctx, safe)
	logger.Printf("store.WriteUnfinishedSafe(%v) => %v", safe, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	hash, err := ethereum.HashMessageForSignature(hex.EncodeToString(t.Message))
	logger.Printf("ethereum.HashMessageForSignature(%s) => %v %s %v", hex.EncodeToString(t.Message), hash, hex.EncodeToString(hash), err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	sr := &store.SignatureRequest{
		TransactionHash: tx.TransactionHash,
		InputIndex:      0,
		Signer:          sp.Signer,
		Curve:           req.Curve,
		Message:         hex.EncodeToString(hash),
		State:           common.RequestStateInitial,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	sr.RequestId = common.UniqueId(req.Id, sr.Message)
	err = node.store.WriteSignatureRequestsWithRequest(ctx, []*store.SignatureRequest{sr}, tx.TransactionHash, req)
	logger.Printf("store.WriteSignatureRequestsWithRequest(%s, %d, %v) => %v", tx.TransactionHash, 1, req, err)
	if err != nil {
		return fmt.Errorf("store.WriteSignatureRequestsWithRequest(%s) => %v", tx.TransactionHash, err)
	}
	err = node.sendSignerSignRequest(ctx, sr, sp.Path)
	logger.Printf("store.sendSignerSignRequest(%v, %s) => %v", sr, sp.Path, err)
	if err != nil {
		return fmt.Errorf("node.sendSignerSignRequest(%v) => %v", sr, err)
	}
	return nil
}

func (node *Node) processEthereumSafeProposeTransaction(ctx context.Context, req *common.Request) error {
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

	assetId := SafeEthereumChainId
	switch safe.Chain {
	case SafeChainEthereum:
	case SafeChainMVM:
		assetId = SafeMVMChainId
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
	if crypto.NewHash([]byte(req.AssetId)) != bondId {
		return node.store.FailRequest(ctx, req.Id)
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) < 33 {
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

	chainId := ethereum.GetEvmChainID(int64(safe.Chain))
	rpc, _ := node.ethereumParams(safe.Chain)
	nonce, err := ethereum.GetNonce(rpc, safe.Address)
	logger.Printf("ethereum.GetNonce(%s) => %d %v", safe.Address, nonce, err)

	var outputs []*ethereum.Output
	ver, _ := common.ReadKernelTransaction(node.conf.MixinRPC, req.MixinHash)
	if len(extra[16:]) == 32 && len(ver.References) == 1 && ver.References[0].String() == hex.EncodeToString(extra[16:]) {
		stx, _ := common.ReadKernelTransaction(node.conf.MixinRPC, ver.References[0])
		extra := common.DecodeMixinObjectExtra(stx.Extra)
		var recipients [][2]string // TODO better encoding
		err = json.Unmarshal(extra, &recipients)
		if err != nil {
			return node.store.FailRequest(ctx, req.Id)
		}
		var total decimal.Decimal
		n := nonce
		for _, rp := range recipients {
			amt, err := decimal.NewFromString(rp[1])
			if err != nil {
				return node.store.FailRequest(ctx, req.Id)
			}
			if amt.Cmp(plan.TransactionMinimum) < 0 {
				return node.store.FailRequest(ctx, req.Id)
			}
			total = total.Add(amt)
			outputs = append(outputs, &ethereum.Output{
				Destination: string(extra[16:]),
				Wei:         ethereum.ParseWei(req.Amount.String()),
				Nonce:       n,
			})
			n += 1
		}
		if !total.Equal(req.Amount) {
			return node.store.FailRequest(ctx, req.Id)
		}
	} else {
		outputs = []*ethereum.Output{{
			Destination: string(extra[16:]),
			Wei:         ethereum.ParseWei(req.Amount.String()),
			Nonce:       nonce,
		}}
	}

	total := decimal.Zero
	recipients := make([]map[string]string, len(outputs))
	for i, out := range outputs {
		amt := decimal.New(out.Wei, -ethereum.ValuePrecision)
		recipients[i] = map[string]string{
			"receiver": out.Destination, "amount": amt.String(),
		}
		total = total.Add(amt)
	}
	if !total.Equal(req.Amount) {
		return node.store.FailRequest(ctx, req.Id)
	}

	// todo: func multicall encoding
	t, err := ethereum.CreateTransaction(ctx, false, rpc, chainId, safe.Address, outputs[0].Destination, outputs[0].Wei, big.NewInt(outputs[0].Nonce))
	logger.Printf("ethereum.CreateTransaction(%s, %d, %s, %s, %d, %d) => %v %v",
		rpc, chainId, safe.Address, outputs[0].Destination, outputs[0].Wei, outputs[0].Nonce, t, err)

	extra = uuid.Must(uuid.FromString(req.Id)).Bytes()
	extra = append(extra, t.Marshal()...)
	exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(extra)))
	typ := byte(common.ActionEthereumSafeProposeTransaction)
	crv := SafeChainCurve(safe.Chain)
	err = node.sendObserverResponseWithReferences(ctx, req.Id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", req.Id, exk, err)
	}

	data := common.MarshalJSONOrPanic(recipients)
	tx := &store.Transaction{
		TransactionHash: t.Hash(req.Id),
		RawTransaction:  hex.EncodeToString(t.Marshal()),
		Holder:          req.Holder,
		Chain:           safe.Chain,
		AssetId:         assetId,
		State:           common.RequestStateInitial,
		Data:            string(data),
		RequestId:       req.Id,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	var transacionInputs []*store.TransactionInput
	return node.store.WriteTransactionWithRequest(ctx, tx, transacionInputs)
}

func (node *Node) processEthereumSafeRevokeTransaction(ctx context.Context, req *common.Request) error {
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

	assetId := SafeEthereumChainId
	switch safe.Chain {
	case SafeChainEthereum:
	case SafeChainMVM:
		assetId = SafeMVMChainId
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

	msg := []byte(fmt.Sprintf("REVOKE:%s:%s", rid.String(), tx.TransactionHash))
	err = ethereum.VerifyMessageSignature(req.Holder, msg, extra[16:])
	logger.Printf("holder: ethereum.VerifyMessageSignature(%v) => %v", req, err)
	if err != nil {
		err = ethereum.VerifyMessageSignature(safe.Observer, msg, extra[16:])
		logger.Printf("observer: ethereum.VerifyMessageSignature(%v) => %v", req, err)
		if err != nil {
			return node.store.FailRequest(ctx, req.Id)
		}
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

func (node *Node) processEthereumSafeApproveTransaction(ctx context.Context, req *common.Request) error {
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
	} else if tx.Holder != req.Holder {
		return node.store.FailRequest(ctx, req.Id)
	}

	var ref crypto.Hash
	copy(ref[:], extra[16:])
	raw := node.readStorageExtraFromObserver(ctx, ref)
	t, err := ethereum.UnmarshalSafeTransaction(raw)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%s) => %v %v", hex.EncodeToString(raw), t, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	_, pubs, err := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	logger.Printf("ethereum.GetSortedSafeOwners(%s %s %s) => %v %v", safe.Holder, safe.Signer, safe.Observer, pubs, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	signed := false
	for i, pub := range pubs {
		if pub == safe.Holder {
			if t.Signatures[i] == nil {
				logger.Printf("Holder not sign this tx")
				continue
			}
			err = ethereum.VerifyMessageSignature(pub, t.Message, t.Signatures[i])
			logger.Printf("ethereum.VerifyMessageSignature(%s %s %s) => %v",
				pub, hex.EncodeToString(t.Message), hex.EncodeToString(t.Signatures[i]), err)
			if err == nil {
				signed = true
			}
		}
	}
	if !signed {
		return node.store.FailRequest(ctx, req.Id)
	}

	err = node.store.UpdateInitialTransaction(ctx, tx.TransactionHash, hex.EncodeToString(t.Marshal()))
	logger.Printf("store.UpdateInitialTransaction(%v) => %v", tx, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	hash, err := ethereum.HashMessageForSignature(hex.EncodeToString(t.Message))
	logger.Printf("ethereum.HashMessageForSignature(%s) => %v %s %v", hex.EncodeToString(t.Message), hash, hex.EncodeToString(hash), err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	sr := &store.SignatureRequest{
		TransactionHash: tx.TransactionHash,
		InputIndex:      0,
		Signer:          safe.Signer,
		Curve:           req.Curve,
		Message:         hex.EncodeToString(hash),
		State:           common.RequestStateInitial,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	sr.RequestId = common.UniqueId(req.Id, sr.Message)
	err = node.store.WriteSignatureRequestsWithRequest(ctx, []*store.SignatureRequest{sr}, tx.TransactionHash, req)
	logger.Printf("store.WriteSignatureRequestsWithRequest(%s, %d, %v) => %v", tx.TransactionHash, 1, req, err)
	if err != nil {
		return fmt.Errorf("store.WriteSignatureRequestsWithRequest(%s) => %v", tx.TransactionHash, err)
	}
	err = node.sendSignerSignRequest(ctx, sr, safe.Path)
	logger.Printf("store.sendSignerSignRequest(%v, %s) => %v", sr, safe.Path, err)
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
	safe, err := node.store.ReadSafe(ctx, tx.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", tx.Holder, err)
	}
	if safe.Signer != req.Holder {
		return node.store.FailRequest(ctx, req.Id)
	}

	sig, _ := hex.DecodeString(req.Extra)
	msg := common.DecodeHexOrPanic(old.Message)
	err = ethereum.VerifyHashSignature(safe.Signer, msg, sig)
	logger.Printf("node.VerifyHashSignature(%v) => %v", req, err)
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

	owners, pubs, err := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	logger.Printf("ethereum.GetSortedSafeOwners(%v) => %v %v", safe, pubs, err)
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
		if pub == safe.Signer {
			sig := common.DecodeHexOrPanic(requests[0].Signature.String)
			sig = ethereum.ProcessSignature(sig)
			err = ethereum.VerifyMessageSignature(safe.Signer, t.Message, sig)
			if err != nil {
				panic(requests[0].Signature.String)
			}
			t.Signatures[i] = sig
		}
	}
	raw := hex.EncodeToString(t.Marshal())
	err = node.store.FinishTransactionSignaturesWithRequest(ctx, old.TransactionHash, raw, req, 0, tx.Chain)
	logger.Printf("store.FinishTransactionSignaturesWithRequest(%s, %s, %v) => %v", old.TransactionHash, raw, req, err)

	if safe.State == common.RequestStatePending {
		var index int64
		for i, pub := range pubs {
			if pub == safe.Observer {
				index = int64(i)
			}
		}
		rpc, _ := node.ethereumParams(tx.Chain)
		safeaddress, err := ethereum.GetOrDeploySafeAccount(rpc, node.conf.EVMKey, owners, 2, int64(safe.Timelock), index, t)
		logger.Printf("ethereum.GetOrDeploySafeAccount(%s, %v, %d, %d, %v) => %s %v", rpc, owners, 2, int64(safe.Timelock), t, safeaddress.Hex(), err)
		if err != nil {
			return err
		}

		sp, err := node.store.ReadSafeProposalByAddress(ctx, safe.Address)
		if err != nil {
			return fmt.Errorf("store.ReadSafeProposalByAddress(%s) => %v", safe.Address, err)
		}
		spr, err := node.store.ReadRequest(ctx, sp.RequestId)
		if err != nil {
			return fmt.Errorf("store.ReadRequest(%s) => %v", sp.RequestId, err)
		}
		exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(safe.Extra)))
		typ := byte(common.ActionEthereumSafeApproveAccount)
		crv := SafeChainCurve(safe.Chain)
		id := common.UniqueId(req.Id, safeaddress.Hex())
		err = node.sendObserverResponseWithAssetAndReferences(ctx, id, typ, crv, spr.AssetId, spr.Amount.String(), exk)
		if err != nil {
			return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", req.Id, exk, err)
		}

		return node.store.FinishedSafeWithRequest(ctx, safe, req.Id)
	}

	exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(t.Marshal())))
	id := common.UniqueId(old.TransactionHash, hex.EncodeToString(exk[:]))
	typ := byte(common.ActionEthereumSafeApproveTransaction)
	crv := SafeChainCurve(safe.Chain)
	err = node.sendObserverResponseWithReferences(ctx, id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", id, exk, err)
	}
	return nil
}
