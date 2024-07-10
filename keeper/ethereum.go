package keeper

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

func (node *Node) processEthereumSafeCloseAccount(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	chain := common.SafeCurveChain(req.Curve)
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err))
	}
	if safe == nil || safe.Chain != chain {
		return node.failRequest(ctx, req, "")
	}
	switch safe.State {
	case SafeStateApproved, SafeStateClosed:
	default:
		return node.failRequest(ctx, req, "")
	}

	meta, err := node.fetchAssetMeta(ctx, req.AssetId)
	logger.Printf("node.fetchAssetMeta(%s) => %v %v", req.AssetId, meta, err)
	if err != nil {
		panic(fmt.Errorf("node.fetchAssetMeta(%s) => %v", req.AssetId, err))
	}
	if meta.Chain != common.SafeChainPolygon {
		return node.failRequest(ctx, req, "")
	}

	rpc, _ := node.ethereumParams(safe.Chain)
	latestTxTime, err := ethereum.GetSafeLastTxTime(rpc, safe.Address)
	logger.Printf("ethereum.GetSafeLastTxTime(%s) => %v %v", safe.Address, latestTxTime, err)
	if err != nil {
		panic(err)
	}
	info, err := node.store.ReadLatestNetworkInfo(ctx, safe.Chain, req.CreatedAt)
	logger.Printf("store.ReadLatestNetworkInfo(%d) => %v %v", safe.Chain, info, err)
	if err != nil {
		panic(err)
	}
	if info == nil {
		return node.failRequest(ctx, req, "")
	}
	latest, err := ethereum.RPCGetBlock(rpc, info.Hash)
	logger.Printf("ethereum.RPCGetBlock(%s %s) => %v %v", rpc, info.Hash, latest, err)
	if err != nil {
		panic(err)
	}
	if latest.Time.IsZero() || latestTxTime.Add(safe.Timelock+1*time.Hour).After(latest.Time) {
		panic(fmt.Errorf("safe %s is locked", safe.Address))
	}

	extra := req.ExtraBytes()
	if len(extra) != 48 {
		return node.failRequest(ctx, req, "")
	}
	var ref crypto.Hash
	copy(ref[:], extra[16:])
	raw := node.readStorageExtraFromObserver(ctx, ref)

	t, err := ethereum.UnmarshalSafeTransaction(raw)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%x) => %v %v", raw, t, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	signedByObserver, err := node.checkEthereumTransactionSignedBy(safe, t, safe.Observer)
	logger.Printf("node.checkEthereumTransactionSignedBy(%v, %s) => %t %v", t, safe.Observer, signedByObserver, err)
	if err != nil {
		panic(err)
	} else if !signedByObserver {
		return node.failRequest(ctx, req, "")
	}
	if t.Destination.Hex() == safe.Address {
		return node.failRequest(ctx, req, "")
	}

	sbm, err := node.store.ReadAllEthereumTokenBalancesMap(ctx, safe.Address)
	logger.Printf("store.ReadAllEthereumTokenBalancesMap(%s) => %v %v", safe.Address, sbm, err)
	if err != nil {
		panic(err)
	}
	outputs := t.ExtractOutputs()
	if len(outputs) != len(sbm) {
		return node.failRequest(ctx, req, "")
	}

	destination := outputs[0].Destination
	for i, o := range outputs {
		if destination != o.Destination {
			logger.Printf("invalid close outputs destination: %d, %v", i, o)
			return node.failRequest(ctx, req, "")
		}

		sbb := sbm[o.TokenAddress].BigBalance()
		if sbb.Cmp(o.Amount) != 0 {
			logger.Printf("inconsistent amount between %s balance and output: %d, %d", o.TokenAddress, sbb, o.Amount)
			return node.failRequest(ctx, req, "")
		}
	}

	count, err := node.store.CountUnfinishedTransactionsByHolder(ctx, safe.Holder)
	logger.Printf("store.CountUnfinishedTransactionsByHolder(%s) => %d %v", safe.Holder, count, err)
	if err != nil {
		panic(err)
	}

	rid, err := uuid.FromBytes(extra[:16])
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	if rid.String() == uuid.Nil.String() {
		if count != 0 {
			return node.failRequest(ctx, req, "")
		}
		txs, asset := node.closeEthereumAccountWithHolder(ctx, req, safe, raw, t.Destination.Hex())
		logger.Printf("node.closeEthereumAccountWithHolder(%v, %s) => %v %s", req, t.Destination.Hex(), txs, asset)
		if err != nil {
			panic(err)
		}
		return txs, asset
	}

	if count != 1 {
		return node.failRequest(ctx, req, "")
	}
	tx, err := node.store.ReadTransactionByRequestId(ctx, rid.String())
	if err != nil {
		panic(fmt.Errorf("store.ReadTransactionByRequestId(%v) => %s %v", req, rid.String(), err))
	} else if tx == nil {
		return node.failRequest(ctx, req, "")
	} else if tx.State == common.RequestStateDone {
		return node.failRequest(ctx, req, "")
	} else if tx.Holder != req.Holder {
		return node.failRequest(ctx, req, "")
	}
	b := common.DecodeHexOrPanic(tx.RawTransaction)
	proposedTx, _ := ethereum.UnmarshalSafeTransaction(b)
	if !bytes.Equal(t.Message, proposedTx.Message) {
		logger.Printf("Inconsistent safe tx message: %x %x", t.Message, proposedTx.Message)
		return node.failRequest(ctx, req, "")
	}

	hash := ethereum.HashMessageForSignature(hex.EncodeToString(t.Message))
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

	txs := node.buildSignerSignRequests(ctx, req, []*store.SignatureRequest{sr}, safe.Path)
	if len(txs) == 0 {
		return node.failRequest(ctx, req, "")
	}
	signedRaw := hex.EncodeToString(t.Marshal())
	if safe.State == SafeStateApproved {
		err = node.store.CloseAccountBySignatureRequestsWithRequest(ctx, []*store.SignatureRequest{sr}, tx.TransactionHash, signedRaw, req, txs)
		logger.Printf("store.CloseAccountBySignatureRequestsWithRequest(%s, %v, %v) => %v", tx.TransactionHash, sr, req, err)
		if err != nil {
			panic(fmt.Errorf("store.WriteSignatureRequestsWithRequest(%s) => %v", tx.TransactionHash, err))
		}
	} else {
		err = node.store.WriteSignatureRequestsWithRequest(ctx, []*store.SignatureRequest{sr}, tx.TransactionHash, signedRaw, req, txs)
		logger.Printf("store.WriteSignatureRequestsWithRequest(%s, %d, %v) => %v", tx.TransactionHash, 1, req, err)
		if err != nil {
			panic(fmt.Errorf("store.WriteSignatureRequestsWithRequest(%s) => %v", tx.TransactionHash, err))
		}
	}
	return txs, ""
}

func (node *Node) closeEthereumAccountWithHolder(ctx context.Context, req *common.Request, safe *store.Safe, raw []byte, receiver string) ([]*mtg.Transaction, string) {
	t, _ := ethereum.UnmarshalSafeTransaction(raw)
	signedByHolder, err := node.checkEthereumTransactionSignedBy(safe, t, safe.Holder)
	logger.Printf("node.checkEthereumTransactionSignedBy(%v, %s) => %t %v", t, safe.Holder, signedByHolder, err)
	if err != nil {
		panic(err)
	} else if !signedByHolder {
		return node.failRequest(ctx, req, "")
	}

	outputs := t.ExtractOutputs()
	recipients := make([]map[string]string, len(outputs))
	for i, out := range outputs {
		norm := ethereum.NormalizeAddress(out.Destination)
		if norm == ethereum.EthereumEmptyAddress || norm == safe.Address {
			logger.Printf("invalid output destination: %s, %s", norm, safe.Address)
			return node.failRequest(ctx, req, "")
		}
		decimals := int32(ethereum.ValuePrecision)
		if out.TokenAddress != ethereum.EthereumEmptyAddress {
			assetId := ethereum.GenerateAssetId(safe.Chain, out.TokenAddress)
			asset, err := node.store.ReadAssetMeta(ctx, assetId)
			logger.Printf("store.ReadAssetMeta(%s) => %v %v", assetId, asset, err)
			if err != nil {
				panic(err)
			}
			decimals = int32(asset.Decimals)
		}
		amt := decimal.NewFromBigInt(out.Amount, -decimals)
		r := map[string]string{
			"receiver": out.Destination, "amount": amt.String(),
		}
		if out.TokenAddress != ethereum.EthereumEmptyAddress {
			r["token"] = out.TokenAddress
		}
		recipients[i] = r
	}
	data := common.MarshalJSONOrPanic(recipients)

	tx := &store.Transaction{
		TransactionHash: t.TxHash,
		RawTransaction:  hex.EncodeToString(raw),
		Holder:          req.Holder,
		Chain:           safe.Chain,
		State:           common.RequestStateDone,
		Data:            string(data),
		RequestId:       req.Id,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	stx := node.buildStorageTransaction(ctx, req, []byte(common.Base91Encode(t.Marshal())))
	if stx == nil {
		return node.failRequest(ctx, req, "")
	}
	txs := []*mtg.Transaction{stx}

	id := common.UniqueId(tx.TransactionHash, stx.TraceId)
	typ := byte(common.ActionEthereumSafeApproveTransaction)
	crv := common.SafeChainCurve(safe.Chain)
	tt := node.buildObserverResponseWithStorageTraceId(ctx, id, req.Sequence, typ, crv, stx.TraceId)
	if tt == nil {
		return node.failRequest(ctx, req, node.conf.ObserverAssetId)
	}
	txs = append(txs, tt)

	err = node.store.CloseAccountByTransactionWithRequest(ctx, tx, nil, common.RequestStateDone, txs)
	if err != nil {
		panic(err)
	}
	return txs, ""
}

func (node *Node) processEthereumSafeProposeAccount(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleHolder {
		panic(req.Role)
	}
	switch req.Curve {
	case common.CurveSecp256k1ECDSAEthereum, common.CurveSecp256k1ECDSAMVM, common.CurveSecp256k1ECDSAPolygon:
	default:
		panic(req.Curve)
	}
	rce := req.ExtraBytes()
	ver, _ := common.ReadKernelTransaction(node.conf.MixinRPC, req.MixinHash)
	if len(rce) == 32 && len(ver.References) == 1 && bytes.Equal(ver.References[0][:], rce) {
		stx, _ := common.ReadKernelTransaction(node.conf.MixinRPC, ver.References[0])
		rce = stx.Extra
	}
	arp, err := req.ParseMixinRecipient(rce)
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
		return node.failRequest(ctx, req, "")
	}
	old, err := node.store.ReadSafeProposal(ctx, req.Id)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafeProposal(%s) => %v", req.Id, err))
	} else if old != nil {
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

	rpc, assetId := node.ethereumParams(chain)
	gs, t, err := ethereum.BuildGnosisSafe(ctx, rpc, req.Holder, signer, observer, req.Id, arp.Timelock, chain)
	logger.Verbosef("ethereum.BuildGnosisSafe(%v) => %v %v", req, gs, err)
	if err != nil {
		panic(err)
	}
	old, err = node.store.ReadSafeProposalByAddress(ctx, gs.Address)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafeProposalByAddress(%s) => %v", gs.Address, err))
	} else if old != nil {
		return node.failRequest(ctx, req, "")
	}

	tx := &store.Transaction{
		TransactionHash: t.TxHash,
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

	extra := gs.Marshal()
	stx := node.buildStorageTransaction(ctx, req, []byte(common.Base91Encode(extra)))
	if stx == nil {
		return node.refundAndFailRequest(ctx, req, arp.Receivers, int(arp.Threshold))
	}
	txs := []*mtg.Transaction{stx}

	typ := byte(common.ActionEthereumSafeProposeAccount)
	crv := common.SafeChainCurve(chain)
	tt := node.buildObserverResponseWithStorageTraceId(ctx, req.Id, req.Sequence, typ, crv, stx.TraceId)
	if tt == nil {
		return node.failRequest(ctx, req, node.conf.ObserverAssetId)
	}
	txs = append(txs, tt)

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
	err = node.store.WriteEthereumSafeProposalWithRequest(ctx, sp, tx, txs)
	if err != nil {
		panic(err)
	}
	return txs, ""
}

func (node *Node) processEthereumSafeApproveAccount(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	switch req.Curve {
	case common.CurveSecp256k1ECDSAEthereum, common.CurveSecp256k1ECDSAMVM, common.CurveSecp256k1ECDSAPolygon:
	default:
		panic(req.Curve)
	}
	old, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err))
	} else if old != nil {
		return node.failRequest(ctx, req, "")
	}
	chain := common.SafeCurveChain(req.Curve)
	_, assetId := node.ethereumParams(chain)
	safeAssetId := node.getBondAssetId(ctx, node.conf.PolygonKeeperDepositEntry, assetId, req.Holder)

	extra := req.ExtraBytes()
	if len(extra) < 64 {
		return node.failRequest(ctx, req, "")
	}
	rid, err := uuid.FromBytes(extra[:16])
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	sp, err := node.store.ReadSafeProposal(ctx, rid.String())
	if err != nil {
		panic(fmt.Errorf("store.ReadSafeProposal(%v) => %s %v", req, rid.String(), err))
	} else if sp == nil {
		return node.failRequest(ctx, req, "")
	} else if sp.Holder != req.Holder {
		return node.failRequest(ctx, req, "")
	} else if sp.Chain != chain {
		return node.failRequest(ctx, req, "")
	}

	gs, err := ethereum.UnmarshalGnosisSafe(sp.Extra)
	logger.Printf("ethereum.UnmarshalGnosisSafe(%s) => %v %v", sp.Extra, gs, err)
	if err != nil {
		panic(err)
	}
	tx, err := node.store.ReadTransaction(ctx, gs.TxHash)
	if err != nil {
		panic(fmt.Errorf("store.ReadTransaction(%s) => %v %v", gs.TxHash, tx, err))
	}
	if tx == nil {
		return node.failRequest(ctx, req, "")
	}
	rawB := common.DecodeHexOrPanic(tx.RawTransaction)
	t, err := ethereum.UnmarshalSafeTransaction(rawB)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%v) => %v %v", rawB, t, err)
	if err != nil {
		panic(err)
	}

	err = ethereum.VerifyMessageSignature(req.Holder, t.Message, extra[16:])
	logger.Printf("ethereum.VerifyMessageSignature(%v) => %v", req, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	_, pubs := ethereum.GetSortedSafeOwners(sp.Holder, sp.Signer, sp.Observer)
	logger.Printf("ethereum.GetSortedSafeOwners(%s, %s, %s) => %v", sp.Holder, sp.Signer, sp.Observer, pubs)
	for i, pub := range pubs {
		if pub == sp.Holder {
			t.Signatures[i] = extra[16:]
		}
	}
	err = node.store.UpdateInitialTransaction(ctx, tx.TransactionHash, hex.EncodeToString(t.Marshal()))
	if err != nil {
		panic(fmt.Errorf("store.UpdateInitialTransaction(%v) => %v", tx, err))
	}

	safe := &store.Safe{
		Holder:      sp.Holder,
		Chain:       sp.Chain,
		Signer:      sp.Signer,
		Observer:    sp.Observer,
		Timelock:    sp.Timelock,
		Path:        sp.Path,
		Address:     sp.Address,
		Extra:       sp.Extra,
		Receivers:   sp.Receivers,
		Threshold:   sp.Threshold,
		RequestId:   req.Id,
		State:       SafeStatePending,
		Nonce:       0,
		SafeAssetId: safeAssetId,
		CreatedAt:   req.CreatedAt,
		UpdatedAt:   req.CreatedAt,
	}
	err = node.store.WriteUnfinishedSafe(ctx, safe)
	if err != nil {
		panic(fmt.Errorf("store.WriteUnfinishedSafe(%v) => %v", safe, err))
	}

	hash := ethereum.HashMessageForSignature(hex.EncodeToString(t.Message))
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
	txs := node.buildSignerSignRequests(ctx, req, []*store.SignatureRequest{sr}, safe.Path)
	if len(txs) == 0 {
		return node.failRequest(ctx, req, "")
	}

	err = node.store.WriteSignatureRequestsWithRequest(ctx, []*store.SignatureRequest{sr}, tx.TransactionHash, "", req, txs)
	logger.Printf("store.WriteSignatureRequestsWithRequest(%s, %d, %v) => %v", tx.TransactionHash, 1, req, err)
	if err != nil {
		panic(err)
	}
	return txs, ""
}

func (node *Node) processEthereumSafeProposeTransaction(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleHolder {
		panic(req.Role)
	}
	chain := common.SafeCurveChain(req.Curve)
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err))
	}
	if safe == nil || safe.Chain != chain {
		return node.failRequest(ctx, req, "")
	}
	if safe.State != SafeStateApproved {
		return node.failRequest(ctx, req, "")
	}

	pendings, err := node.store.ReadUnfinishedTransactionsByHolder(ctx, safe.Holder)
	logger.Printf("store.ReadUnfinishedTransactionsByHolder(%s) => %v %v", safe.Holder, len(pendings), err)
	if len(pendings) > 0 {
		return node.failRequest(ctx, req, "")
	}

	meta, err := node.fetchAssetMeta(ctx, req.AssetId)
	logger.Printf("node.fetchAssetMeta(%s) => %v %v", req.AssetId, meta, err)
	if err != nil {
		panic(fmt.Errorf("node.fetchAssetMeta(%s) => %v", req.AssetId, err))
	}
	if meta.Chain != common.SafeChainPolygon {
		return node.failRequest(ctx, req, "")
	}
	deployed, err := abi.CheckFactoryAssetDeployed(node.conf.PolygonRPC, meta.AssetKey)
	logger.Printf("abi.CheckFactoryAssetDeployed(%s) => %v %v", meta.AssetKey, deployed, err)
	if err != nil || deployed.Sign() <= 0 {
		panic(fmt.Errorf("api.CheckFatoryAssetDeployed(%s) => %v", meta.AssetKey, err))
	}
	id := uuid.Must(uuid.FromBytes(deployed.Bytes()))

	plan, err := node.store.ReadLatestOperationParams(ctx, safe.Chain, req.CreatedAt)
	logger.Printf("store.ReadLatestOperationParams(%d) => %v %v", safe.Chain, plan, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadLatestOperationParams(%d) => %v", safe.Chain, err))
	} else if plan == nil || !plan.TransactionMinimum.IsPositive() {
		return node.refundAndFailRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}
	if req.Amount.Cmp(plan.TransactionMinimum) < 0 {
		return node.failRequest(ctx, req, "")
	}

	entry := node.fetchBondAssetReceiver(ctx, safe.Address, id.String())
	safeAssetId := node.getBondAssetId(ctx, entry, id.String(), req.Holder)
	logger.Printf("node.getBondAssetId(%s, %s, %s) => %s", entry, id.String(), req.Holder, safeAssetId)
	if req.AssetId != safeAssetId {
		panic(req.AssetId)
	}

	extra := req.ExtraBytes()
	if len(extra) < 33 {
		return node.failRequest(ctx, req, "")
	}
	flag, extra := extra[0], extra[1:]
	iid, err := uuid.FromBytes(extra[:16])
	if err != nil || iid.String() == uuid.Nil.String() {
		return node.failRequest(ctx, req, "")
	}
	info, err := node.store.ReadNetworkInfo(ctx, iid.String())
	logger.Printf("store.ReadNetworkInfo(%s) => %v %v", iid.String(), info, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadNetworkInfo(%s) => %v", iid.String(), err))
	}
	if info == nil || info.Chain != safe.Chain {
		return node.failRequest(ctx, req, "")
	}
	balance, err := node.store.ReadEthereumBalance(ctx, safe.Address, id.String(), safeAssetId)
	logger.Printf("store.ReadEthereumBalance(%s, %s) => %v %v", safe.Address, id.String(), balance, err)
	if err != nil {
		panic(err)
	}
	if ethereum.NormalizeAddress(balance.AssetAddress) != balance.AssetAddress {
		panic(balance.AssetAddress)
	}
	if balance.SafeAssetId != req.AssetId {
		panic(balance.SafeAssetId)
	}
	decimals := int32(ethereum.ValuePrecision)
	if balance.AssetAddress != ethereum.EthereumEmptyAddress {
		asset, err := node.store.ReadAssetMeta(ctx, id.String())
		logger.Printf("store.ReadAssetMeta(%s) => %v %v", id.String(), asset, err)
		if err != nil {
			panic(err)
		}
		decimals = int32(asset.Decimals)
	}

	var outputs []*ethereum.Output
	ver, _ := common.ReadKernelTransaction(node.conf.MixinRPC, req.MixinHash)
	if len(extra[16:]) == 32 && len(ver.References) == 1 && ver.References[0].String() == hex.EncodeToString(extra[16:]) {
		stx, _ := common.ReadKernelTransaction(node.conf.MixinRPC, ver.References[0])
		extra := stx.Extra
		var recipients [][2]string // TODO better encoding
		err = json.Unmarshal(extra, &recipients)
		if err != nil {
			return node.failRequest(ctx, req, "")
		}
		for _, rp := range recipients {
			amt, err := decimal.NewFromString(rp[1])
			if err != nil {
				return node.failRequest(ctx, req, "")
			}
			if amt.Cmp(plan.TransactionMinimum) < 0 {
				return node.failRequest(ctx, req, "")
			}
			o := &ethereum.Output{
				Destination:  rp[0],
				Amount:       ethereum.ParseAmount(amt.String(), decimals),
				TokenAddress: balance.AssetAddress,
			}
			outputs = append(outputs, o)
		}
	} else {
		outputs = []*ethereum.Output{{
			Destination:  string(extra[16:]),
			Amount:       ethereum.ParseAmount(req.Amount.String(), decimals),
			TokenAddress: balance.AssetAddress,
		}}
	}

	total := decimal.Zero
	recipients := make([]map[string]string, len(outputs))
	for i, out := range outputs {
		norm := ethereum.NormalizeAddress(out.Destination)
		if norm == ethereum.EthereumEmptyAddress || norm == safe.Address {
			logger.Printf("invalid output destination: %s, %s", norm, safe.Address)
			return node.failRequest(ctx, req, "")
		}
		amt := decimal.NewFromBigInt(out.Amount, -decimals)
		r := map[string]string{
			"receiver": out.Destination, "amount": amt.String(),
		}
		if out.TokenAddress != ethereum.EthereumEmptyAddress {
			r["token"] = out.TokenAddress
		}
		recipients[i] = r
		total = total.Add(amt)
	}
	if len(outputs) > 256 {
		logger.Printf("invalid count of outputs: %d", len(outputs))
		return node.refundAndFailRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}
	if !total.Equal(req.Amount) {
		logger.Printf("inconsistent amount between total outputs %d and %d", total, req.Amount)
		return node.failRequest(ctx, req, "")
	}

	var t *ethereum.SafeTransaction
	chainId := ethereum.GetEvmChainID(int64(safe.Chain))
	txType := ethereum.TypeETHTx
	switch flag {
	case common.FlagProposeNormalTransaction:
		switch {
		case len(outputs) > 1:
			txType = ethereum.TypeMultiSendTx
		case balance.AssetAddress != ethereum.EthereumEmptyAddress:
			txType = ethereum.TypeERC20Tx
		}
		t, err = ethereum.CreateTransactionFromOutputs(ctx, txType, chainId, req.Id, safe.Address, outputs, big.NewInt(safe.Nonce))
		logger.Printf("ethereum.CreateTransactionFromOutputs(%d, %d, %s, %s, %v, %d) => %v %v",
			txType, chainId, req.Id, safe.Address, outputs, safe.Nonce, t, err)
		if err != nil {
			panic(err)
		}
	case common.FlagProposeRecoveryTransaction:
		if len(outputs) != 1 {
			logger.Printf("invalid recovery transaction outputs: %d", len(outputs))
			return node.failRequest(ctx, req, "")
		}
		balances, err := node.store.ReadAllEthereumTokenBalances(ctx, safe.Address)
		logger.Printf("store.ReadAllEthereumTokenBalances(%s) => %v %v", safe.Address, balances, err)
		if err != nil {
			panic(err)
		}
		for _, b := range balances {
			if b.AssetId == balance.AssetId || b.BigBalance().Cmp(big.NewInt(0)) == 0 {
				continue
			}
			output := &ethereum.Output{
				Destination:  string(extra[16:]),
				Amount:       b.BigBalance(),
				TokenAddress: b.AssetAddress,
			}
			outputs = append(outputs, output)

			asset, err := node.store.ReadAssetMeta(ctx, b.AssetId)
			logger.Printf("store.ReadAssetMeta(%s) => %v %v", b.AssetId, asset, err)
			if err != nil {
				panic(err)
			}
			amt := decimal.NewFromBigInt(output.Amount, int32(-asset.Decimals))
			r := map[string]string{
				"receiver": output.Destination, "amount": amt.String(),
			}
			if output.TokenAddress != ethereum.EthereumEmptyAddress {
				r["token"] = output.TokenAddress
			}
			recipients = append(recipients, r)
		}
		txType = ethereum.TypeMultiSendTx
		if len(outputs) == 1 {
			txType = ethereum.TypeETHTx
			if outputs[0].TokenAddress != ethereum.EthereumEmptyAddress {
				txType = ethereum.TypeERC20Tx
			}
		}
		t, err = ethereum.CreateTransactionFromOutputs(ctx, txType, chainId, req.Id, safe.Address, outputs, big.NewInt(safe.Nonce))
		logger.Printf("ethereum.CreateTransactionFromOutputs(%d, %d, %s, %s, %v, %d) => %v %v",
			txType, chainId, req.Id, safe.Address, outputs, safe.Nonce, t, err)
		if err != nil {
			panic(err)
		}
	default:
		logger.Printf("invalid transaction flag: %d", flag)
		return node.failRequest(ctx, req, "")
	}

	extra = t.Marshal()
	stx := node.buildStorageTransaction(ctx, req, []byte(common.Base91Encode(extra)))
	if stx == nil {
		return node.refundAndFailRequest(ctx, req, safe.Receivers, int(safe.Threshold))
	}
	txs := []*mtg.Transaction{stx}

	typ := byte(common.ActionEthereumSafeProposeTransaction)
	crv := common.SafeChainCurve(safe.Chain)
	tt := node.buildObserverResponseWithStorageTraceId(ctx, req.Id, req.Sequence, typ, crv, stx.TraceId)
	if tt == nil {
		return node.failRequest(ctx, req, node.conf.ObserverAssetId)
	}
	txs = append(txs, tt)

	data := common.MarshalJSONOrPanic(recipients)
	tx := &store.Transaction{
		TransactionHash: t.TxHash,
		RawTransaction:  hex.EncodeToString(t.Marshal()),
		Holder:          req.Holder,
		Chain:           safe.Chain,
		AssetId:         id.String(),
		State:           common.RequestStateInitial,
		Data:            string(data),
		RequestId:       req.Id,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	err = node.store.WriteTransactionWithRequest(ctx, tx, nil, txs)
	if err != nil {
		panic(err)
	}
	return txs, ""
}

func (node *Node) processEthereumSafeApproveTransaction(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	chain := common.SafeCurveChain(req.Curve)
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err))
	}
	if safe == nil || safe.Chain != chain {
		return node.failRequest(ctx, req, "")
	}

	extra := req.ExtraBytes()
	if len(extra) != 48 {
		return node.failRequest(ctx, req, "")
	}
	rid, err := uuid.FromBytes(extra[:16])
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	tx, err := node.store.ReadTransactionByRequestId(ctx, rid.String())
	if err != nil {
		panic(fmt.Errorf("store.ReadTransactionByRequestId(%v) => %s %v", req, rid.String(), err))
	} else if tx == nil {
		return node.failRequest(ctx, req, "")
	} else if tx.State == common.RequestStateDone {
		return node.failRequest(ctx, req, "")
	} else if tx.Holder != req.Holder {
		return node.failRequest(ctx, req, "")
	}

	var ref crypto.Hash
	copy(ref[:], extra[16:])
	raw := node.readStorageExtraFromObserver(ctx, ref)
	t, err := ethereum.UnmarshalSafeTransaction(raw)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%x) => %v %v", raw, t, err)
	if err != nil {
		panic(err)
	}

	signed, err := node.checkEthereumTransactionSignedBy(safe, t, safe.Holder)
	logger.Printf("node.checkEthereumTransactionSignedBy(%v, %s) => %t %v", t, safe.Holder, signed, err)
	if err != nil {
		panic(err)
	} else if !signed {
		return node.failRequest(ctx, req, "")
	}

	err = node.store.UpdateInitialTransaction(ctx, tx.TransactionHash, hex.EncodeToString(t.Marshal()))
	logger.Printf("store.UpdateInitialTransaction(%v) => %v", tx, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}

	hash := ethereum.HashMessageForSignature(hex.EncodeToString(t.Message))
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
	txs := node.buildSignerSignRequests(ctx, req, []*store.SignatureRequest{sr}, safe.Path)
	if len(txs) == 0 {
		// no compaction needed, just retry from observer
		return node.failRequest(ctx, req, "")
	}
	err = node.store.WriteSignatureRequestsWithRequest(ctx, []*store.SignatureRequest{sr}, tx.TransactionHash, "", req, txs)
	logger.Printf("store.WriteSignatureRequestsWithRequest(%s, %d, %v) => %v", tx.TransactionHash, 1, req, err)
	if err != nil {
		panic(err)
	}
	return txs, ""
}

func (node *Node) processEthereumSafeRefundTransaction(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	chain := common.SafeCurveChain(req.Curve)
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err))
	}
	if safe == nil || safe.Chain != chain {
		return node.failRequest(ctx, req, "")
	}

	extra := req.ExtraBytes()
	if len(extra) != 16 {
		return node.failRequest(ctx, req, "")
	}
	rid, err := uuid.FromBytes(extra)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	tx, err := node.store.ReadTransactionByRequestId(ctx, rid.String())
	if err != nil {
		panic(fmt.Errorf("store.ReadTransactionByRequestId(%v) => %s %v", req, rid.String(), err))
	} else if tx == nil {
		return node.failRequest(ctx, req, "")
	} else if tx.Holder != req.Holder {
		return node.failRequest(ctx, req, "")
	} else if tx.State != common.RequestStateDone {
		return node.failRequest(ctx, req, "")
	}

	b := common.DecodeHexOrPanic(tx.RawTransaction)
	st, err := ethereum.UnmarshalSafeTransaction(b)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%v) => %v %v", b, st, err)
	if err != nil {
		panic(err)
	}

	sbm, err := node.store.ReadAllEthereumTokenBalancesMap(ctx, safe.Address)
	logger.Printf("store.ReadAllEthereumTokenBalancesMap(%s) => %v %v", safe.Address, sbm, err)
	if err != nil {
		panic(err)
	}
	outputs := st.ExtractOutputs()
	for _, o := range outputs {
		sbm[o.TokenAddress].UpdateBalance(o.Amount)
	}

	txRequest, err := node.store.ReadRequest(ctx, tx.RequestId)
	logger.Printf("store.ReadRequest(%s) => %v %v", tx.RequestId, txRequest, err)
	if err != nil {
		panic(err)
	}
	meta, err := node.fetchAssetMeta(ctx, txRequest.AssetId)
	logger.Printf("node.fetchAssetMeta(%s) => %v %v", req.AssetId, meta, err)
	if err != nil {
		panic(fmt.Errorf("node.fetchAssetMeta(%s) => %v", req.AssetId, err))
	}
	if meta.Chain != common.SafeChainPolygon {
		return node.failRequest(ctx, req, "")
	}
	deployed, err := abi.CheckFactoryAssetDeployed(node.conf.PolygonRPC, meta.AssetKey)
	logger.Printf("abi.CheckFactoryAssetDeployed(%s) => %v %v", meta.AssetKey, deployed, err)
	if err != nil || deployed.Sign() <= 0 {
		panic(fmt.Errorf("api.CheckFatoryAssetDeployed(%s) => %v", meta.AssetKey, err))
	}
	tt := node.buildTransaction(ctx, req.Sequence, node.conf.AppId, txRequest.AssetId, safe.Receivers, int(safe.Threshold), ethereum.ParseAmount(req.Amount.String(), int32(meta.Decimals)).String(), []byte("refund"), req.Id)
	if tt == nil {
		return node.failRequest(ctx, req, txRequest.AssetId)
	}

	err = node.store.FailTransactionWithRequest(ctx, tx, safe, req, sbm, []*mtg.Transaction{tt})
	logger.Printf("store.FailTransactionWithRequest(%v %v %v) => %v", tx, safe, req, err)
	if err != nil {
		panic(err)
	}
	return []*mtg.Transaction{tt}, ""
}

func (node *Node) processEthereumSafeSignatureResponse(ctx context.Context, req *common.Request, safe *store.Safe, tx *store.Transaction, old *store.SignatureRequest) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleSigner {
		panic(req.Role)
	}

	sig := req.ExtraBytes()
	msg := common.DecodeHexOrPanic(old.Message)
	err := ethereum.VerifyHashSignature(safe.Signer, msg, sig)
	logger.Printf("node.VerifyHashSignature(%v) => %v", req, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	err = node.store.FinishSignatureRequest(ctx, req)
	logger.Printf("store.FinishSignatureRequest(%s) => %v", req.Id, err)
	if err != nil {
		panic(fmt.Errorf("store.FinishSignatureRequest(%s) => %v", req.Id, err))
	}

	rawB := common.DecodeHexOrPanic(tx.RawTransaction)
	t, err := ethereum.UnmarshalSafeTransaction(rawB)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%v) => %v %v", rawB, t, err)
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
	_, pubs := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	logger.Printf("ethereum.GetSortedSafeOwners(%v) => %v", safe, pubs)
	for i, pub := range pubs {
		if pub != safe.Signer {
			continue
		}
		sig := common.DecodeHexOrPanic(requests[0].Signature.String)
		sig = ethereum.ProcessSignature(sig)
		err = ethereum.VerifyMessageSignature(safe.Signer, t.Message, sig)
		if err != nil {
			panic(requests[0].Signature.String)
		}
		t.Signatures[i] = sig
	}
	raw := hex.EncodeToString(t.Marshal())

	if safe.State == common.RequestStatePending {
		sp, err := node.store.ReadSafeProposalByAddress(ctx, safe.Address)
		if err != nil {
			panic(fmt.Errorf("store.ReadSafeProposalByAddress(%s) => %v", safe.Address, err))
		}
		spr, err := node.store.ReadRequest(ctx, sp.RequestId)
		if err != nil {
			panic(fmt.Errorf("store.ReadRequest(%s) => %v", sp.RequestId, err))
		}

		stx := node.buildStorageTransaction(ctx, req, []byte(common.Base91Encode(safe.Extra)))
		if stx == nil {
			return node.failRequest(ctx, req, "")
		}
		txs := []*mtg.Transaction{stx}

		typ := byte(common.ActionEthereumSafeApproveAccount)
		crv := common.SafeChainCurve(safe.Chain)
		id := common.UniqueId(req.Id, safe.Address)
		tx := node.buildObserverResponseWithAssetAndStorageTraceId(ctx, id, req.Sequence, typ, crv, spr.AssetId, spr.Amount.String(), stx.TraceId)
		if tx == nil {
			return node.failRequest(ctx, req, spr.AssetId)
		}
		txs = append(txs, tx)

		chainId := ethereum.GetEvmChainID(int64(sp.Chain))
		timelock := uint64(sp.Timelock / time.Hour)
		observer, err := ethereum.ParseEthereumCompressedPublicKey(sp.Observer)
		if err != nil {
			panic(fmt.Errorf("ethereum.ParseEthereumCompressedPublicKey(%s) => %v %v", sp.Observer, observer, err))
		}
		gt, err := ethereum.CreateEnableGuardTransaction(ctx, chainId, sp.RequestId, sp.Address, observer.Hex(), new(big.Int).SetUint64(timelock))
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(gt.Data, t.Data) {
			panic(fmt.Errorf("invalid safe guard transaction %x %x", gt.Data, t.Data))
		}

		err = node.store.FinishSafeWithRequest(ctx, old.TransactionHash, raw, req, safe, txs)
		if err != nil {
			panic(err)
		}
		return txs, ""
	}

	sbm, err := node.store.ReadAllEthereumTokenBalancesMap(ctx, safe.Address)
	logger.Printf("store.ReadAllEthereumTokenBalancesMap(%s) => %v %v", safe.Address, sbm, err)
	if err != nil {
		panic(err)
	}
	outputs := t.ExtractOutputs()
	for _, o := range outputs {
		closeBalance := big.NewInt(0).Sub(sbm[o.TokenAddress].BigBalance(), o.Amount)
		if closeBalance.Cmp(big.NewInt(0)) < 0 {
			logger.Printf("safe %s close balance %d lower than 0", safe.Address, closeBalance)
			return node.failRequest(ctx, req, "")
		}
		sbm[o.TokenAddress].UpdateBalance(new(big.Int).Neg(o.Amount))
	}

	stx := node.buildStorageTransaction(ctx, req, []byte(common.Base91Encode(t.Marshal())))
	if stx == nil {
		return node.failRequest(ctx, req, "")
	}
	txs := []*mtg.Transaction{stx}

	id := common.UniqueId(old.TransactionHash, stx.TraceId)
	typ := byte(common.ActionEthereumSafeApproveTransaction)
	crv := common.SafeChainCurve(safe.Chain)
	tt := node.buildObserverResponseWithStorageTraceId(ctx, id, req.Sequence, typ, crv, stx.TraceId)
	if tt == nil {
		return node.failRequest(ctx, req, node.conf.ObserverAssetId)
	}
	txs = append(txs, tt)

	err = node.store.FinishTransactionSignaturesWithRequest(ctx, old.TransactionHash, raw, req, 0, safe, sbm, txs)
	logger.Printf("store.FinishTransactionSignaturesWithRequest(%s, %s, %v) => %v", old.TransactionHash, raw, req, err)
	if err != nil {
		panic(err)
	}
	return txs, ""
}

func (node *Node) checkEthereumTransactionSignedBy(safe *store.Safe, t *ethereum.SafeTransaction, public string) (bool, error) {
	_, pubs := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	logger.Printf("ethereum.GetSortedSafeOwners(%s, %s, %s) => %v", safe.Holder, safe.Signer, safe.Observer, pubs)
	for i, k := range pubs {
		sig := t.Signatures[i]
		if k != public || sig == nil {
			continue
		}
		err := ethereum.VerifyMessageSignature(public, t.Message, sig)
		logger.Printf("ethereum.VerifyMessageSignature(%s, %x, %x) => %v", safe.Holder, t.Message, sig, err)
		return err == nil, nil
	}
	return false, nil
}
