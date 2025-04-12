package keeper

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	sg "github.com/gagliardetto/solana-go"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

func (node *Node) processSolanaSafeCloseAccount(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}

	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err))
	}

	if safe == nil || safe.Chain != common.SafeChainSolana {
		return node.failRequest(ctx, req, "")
	}

	switch safe.State {
	case SafeStateApproved, SafeStateClosed:
	default:
		return node.failRequest(ctx, req, "")
	}

	extra := req.ExtraBytes()
	if len(extra) != 48 {
		return node.failRequest(ctx, req, "")
	}
	var ref crypto.Hash
	copy(ref[:], extra[16:])
	raw := node.readStorageExtraFromObserver(ctx, ref)

	t, err := sg.TransactionFromBytes(raw)
	if err != nil {
		panic(err)
	}

	signed := solana.CheckTransactionSignedBy(t, sg.MPK(safe.Observer))
	logger.Printf("solana.CheckTransactionSignedBy(%v, %s) => %t", t, safe.Observer, signed)
	if !signed {
		return node.failRequest(ctx, req, "")
	}

	sbm, err := node.store.ReadAllSolanaTokenBalancesMap(ctx, safe.Address)
	logger.Printf("store.ReadAllSolanaTokenBalancesMap(%s) => %v %v", safe.Address, sbm, err)
	if err != nil {
		panic(err)
	}

	outputs := solana.ExtractOutputs(t)
	if len(outputs) != len(sbm) {
		return node.failRequest(ctx, req, "")
	}

	destination := outputs[0].Destination
	if destination == safe.Address {
		return node.failRequest(ctx, req, "")
	}

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
		txs, asset := node.closeSolanaAccountWithHolder(ctx, req, safe, raw)
		logger.Printf("node.closeSolanaAccountWithHolder(%v, %s) => %v %s", req, destination, txs, asset)
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
	proposedTx := common.Must(sg.TransactionFromBytes(b))
	if got, want := common.Must(t.Message.MarshalBinary()), common.Must(proposedTx.Message.MarshalBinary()); !bytes.Equal(got, want) {
		logger.Printf("Inconsistent safe tx message: %x %x", got, want)
		return node.failRequest(ctx, req, "")
	}

	sr := &store.SignatureRequest{
		TransactionHash: tx.TransactionHash,
		InputIndex:      0,
		Signer:          safe.Signer,
		Curve:           req.Curve,
		Message:         hex.EncodeToString(common.Must(t.Message.MarshalBinary())),
		State:           common.RequestStateInitial,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	sr.RequestId = common.UniqueId(req.Id, sr.Message)

	txs := node.buildSignerSignRequests(ctx, req, []*store.SignatureRequest{sr}, safe.Path)
	if len(txs) == 0 {
		return node.failRequest(ctx, req, "")
	}

	signedRaw := hex.EncodeToString(common.Must(t.MarshalBinary()))
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

func (node *Node) closeSolanaAccountWithHolder(ctx context.Context, req *common.Request, safe *store.Safe, raw []byte) ([]*mtg.Transaction, string) {
	t := common.Must(sg.TransactionFromBytes(raw))
	signedByHolder := solana.CheckTransactionSignedBy(t, sg.MPK(safe.Holder))
	logger.Printf("node.checkSolanaTransactionSignedBy(%v, %s) => %t", t, safe.Holder, signedByHolder)
	if !signedByHolder {
		return node.failRequest(ctx, req, "")
	}

	outputs := solana.ExtractOutputs(t)
	recipients := make([]map[string]string, len(outputs))
	for i, out := range outputs {
		switch out.Destination {
		case safe.Address, solana.SolanaEmptyAddress:
			logger.Printf("invalid output destination: %s, %s", out.Destination, safe.Address)
			return node.failRequest(ctx, req, "")
		}

		decimals := int32(solana.NativeTokenDecimals)
		if out.TokenAddress != solana.SolanaEmptyAddress {
			assetId := solana.GenerateAssetId(out.TokenAddress)
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
		r["token"] = out.TokenAddress
		recipients[i] = r
	}

	data := common.MarshalJSONOrPanic(recipients)

	tx := &store.Transaction{
		TransactionHash: t.Message.RecentBlockhash.String(),
		RawTransaction:  hex.EncodeToString(raw),
		Holder:          req.Holder,
		Chain:           safe.Chain,
		State:           common.RequestStateDone,
		Data:            string(data),
		RequestId:       req.Id,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}

	stx := node.buildStorageTransaction(ctx, req, []byte(common.Base91Encode(raw)))
	if stx == nil {
		return node.failRequest(ctx, req, "")
	}
	txs := []*mtg.Transaction{stx}

	id := common.UniqueId(tx.TransactionHash, stx.TraceId)
	typ := byte(common.ActionSolanaSafeApproveTransaction)
	crv := common.SafeChainCurve(safe.Chain)
	tt := node.buildObserverResponseWithStorageTraceId(ctx, id, req.Output, typ, crv, stx.TraceId)
	if tt == nil {
		return node.failRequest(ctx, req, "")
	}
	txs = append(txs, tt)

	if err := node.store.CloseAccountByTransactionWithRequest(ctx, tx, nil, common.RequestStateDone, txs, req); err != nil {
		panic(err)
	}
	return txs, ""
}

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

	tx := solana.BuildSquadsSafe(solana.BuildSquadsSafeParams{
		Members:   []sg.PublicKey{solana.MPK(req.Holder), solana.MPK(signer), solana.MPK(observer)},
		Creator:   solana.MPK(req.Holder),
		Nonce:     arp.NonceAccount,
		BlockHash: arp.BlockHash,
		Payer:     arp.PayerAccount,
		Threshold: 2,
	})

	address := solana.GetAuthorityAddressFromCreateTx(tx)
	if address.IsZero() {
		panic("solana.GetAuthorityAddressFromCreateTx(tx) => zero")
	}

	if old, err := node.store.ReadSafeProposalByAddress(ctx, address.String()); err != nil {
		panic(fmt.Errorf("store.ReadSafeProposalByAddress(%s) => %v", address, err))
	} else if old != nil {
		return node.failRequest(ctx, req, "")
	}

	extra, err := tx.MarshalBinary()
	if err != nil {
		panic(err)
	}

	stx := node.buildStorageTransaction(ctx, req, []byte(common.Base91Encode(extra)))
	if stx == nil {
		return node.refundAndFailRequest(ctx, req, arp.Receivers, int(arp.Threshold))
	}
	txs := []*mtg.Transaction{stx}

	typ := byte(common.ActionSolanaSafeProposeAccount)
	crv := common.SafeChainCurve(chain)
	tt := node.buildObserverResponseWithStorageTraceId(ctx, req.Id, req.Output, typ, crv, stx.TraceId)
	if tt == nil {
		return node.refundAndFailRequest(ctx, req, arp.Receivers, int(arp.Threshold))
	}
	txs = append(txs, tt)

	sp := &store.SafeProposal{
		RequestId: req.Id,
		Chain:     chain,
		Holder:    req.Holder,
		Signer:    signer,
		Observer:  observer,
		Timelock:  arp.Timelock,
		Path:      solanaDefaultDerivationPath(),
		Address:   address.String(),
		Extra:     extra,
		Receivers: arp.Receivers,
		Threshold: arp.Threshold,
		CreatedAt: req.CreatedAt,
		UpdatedAt: req.CreatedAt,
	}
	if err := node.store.WriteSafeProposalWithRequest(ctx, sp, txs, req); err != nil {
		panic(err)
	}
	return txs, ""
}

func (node *Node) processSolanaSafeApproveAccount(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}

	if req.Curve != common.CurveEdwards25519Default {
		panic(req.Curve)
	}

	if old, err := node.store.ReadSafe(ctx, req.Holder); err != nil {
		panic(fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err))
	} else if old != nil && old.State != common.RequestStatePending {
		return node.failRequest(ctx, req, "")
	}

	chain := common.SafeCurveChain(req.Curve)
	safeAssetId := node.getBondAssetId(ctx, node.conf.PolygonKeeperDepositEntry, common.SafeSolanaChainId, req.Holder)

	extra := req.ExtraBytes()
	if len(extra) < 16+sg.SignatureLength {
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

	tx, err := sg.TransactionFromBytes(sp.Extra)
	if err != nil {
		panic(err)
	}

	holder := solana.MPK(req.Holder)
	sig := sg.SignatureFromBytes(extra[16:])
	err = solana.AddSignature(tx, holder, sig)
	logger.Printf("solana.AddSignature(%v) => %v", req, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}

	nextExtra, err := tx.MarshalBinary()
	if err != nil {
		panic(err)
	}

	spr, err := node.store.ReadRequest(ctx, sp.RequestId)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafeProposal(%s) => %v", sp.RequestId, err))
	}

	stx := node.buildStorageTransaction(ctx, req, []byte(common.Base91Encode(nextExtra)))
	if stx == nil {
		return node.failRequest(ctx, req, "")
	}
	txs := []*mtg.Transaction{stx}

	typ := byte(common.ActionSolanaSafeApproveAccount)
	crv := common.SafeChainCurve(sp.Chain)
	t := node.buildObserverResponseWithAssetAndStorageTraceId(ctx, req.Id, req.Output, typ, crv, spr.AssetId, spr.Amount.String(), stx.TraceId)
	if t == nil {
		return node.failRequest(ctx, req, spr.AssetId)
	}
	txs = append(txs, t)

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
		State:       SafeStateApproved,
		Nonce:       0,
		SafeAssetId: safeAssetId,
		CreatedAt:   req.CreatedAt,
		UpdatedAt:   req.CreatedAt,
	}

	err = node.store.WriteSafeWithRequest(ctx, safe, txs, req)
	if err != nil {
		panic(err)
	}
	return txs, ""
}

func (node *Node) processSolanaSafeProposeTransaction(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleHolder {
		panic(req.Role)
	}

	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err))
	}

	chain := common.SafeCurveChain(req.Curve)
	if safe.Chain != chain {
		return node.failRequest(ctx, req, "")
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

	txReq, err := solana.DecodeTransactionRequest(req.ExtraBytes())
	if err != nil {
		logger.Printf("solana.DecodeTransactionRequest(%v) => %v", req, err)
		return node.failRequest(ctx, req, "")
	}

	if txReq.RequestID.IsNil() {
		return node.failRequest(ctx, req, "")
	}

	info, err := node.store.ReadNetworkInfo(ctx, txReq.RequestID.String())
	logger.Printf("store.ReadNetworkInfo(%s) => %v %v", txReq.RequestID.String(), info, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadNetworkInfo(%s) => %v", txReq.RequestID.String(), err))
	}
	if info == nil || info.Chain != safe.Chain {
		return node.failRequest(ctx, req, "")
	}

	balance, err := node.store.ReadSolanaBalance(ctx, safe.Address, id.String(), safeAssetId)
	logger.Printf("store.ReadSolanaBalance(%s, %s) => %v %v", safe.Address, id.String(), balance, err)
	if err != nil {
		panic(err)
	}
	if balance.SafeAssetId != req.AssetId {
		panic(balance.SafeAssetId)
	}

	if balance.SafeAssetId != req.AssetId {
		panic(balance.SafeAssetId)
	}

	decimals := int32(solana.NativeTokenDecimals)
	if balance.AssetAddress != solana.SolanaEmptyAddress {
		asset, err := node.store.ReadAssetMeta(ctx, id.String())
		logger.Printf("store.ReadAssetMeta(%s) => %v %v", id.String(), asset, err)
		if err != nil {
			panic(err)
		}

		decimals = int32(asset.Decimals)
	}

	var outputs []*solana.Output
	ver, _ := node.group.ReadKernelTransactionUntilSufficient(ctx, req.MixinHash.String())
	if len(ver.References) == 1 && ver.References[0].String() == hex.EncodeToString(txReq.Extra[:]) {
		stx, _ := node.group.ReadKernelTransactionUntilSufficient(ctx, ver.References[0].String())
		var recipients [][2]string
		err = json.Unmarshal(stx.Extra, &recipients)
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

			o := &solana.Output{
				TokenAddress: balance.AssetAddress,
				Destination:  rp[0],
				Amount:       ethereum.ParseAmount(amt.String(), decimals),
			}
			outputs = append(outputs, o)
		}
	} else {
		outputs = []*solana.Output{{
			TokenAddress: balance.AssetAddress,
			Destination:  sg.PublicKeyFromBytes(txReq.Extra[:]).String(),
			Amount:       ethereum.ParseAmount(req.Amount.String(), decimals),
		}}
	}

	total := decimal.Zero
	recipients := make([]map[string]string, len(outputs))
	for i, out := range outputs {
		dest, err := sg.PublicKeyFromBase58(out.Destination)
		if err != nil || dest.IsZero() || dest.String() == safe.Address {
			logger.Printf("invalid output destination: %s, %s", out.Destination, safe.Address)
			return node.failRequest(ctx, req, "")
		}

		amt := decimal.NewFromBigInt(out.Amount, decimals)
		r := map[string]string{"receiver": out.Destination, "amount": amt.String()}
		if out.TokenAddress != solana.SolanaEmptyAddress {
			r["token"] = out.TokenAddress
		}
		recipients[i] = r
		total = total.Add(amt)
	}

	if len(outputs) > 256 || !total.Equal(req.Amount) {
		return node.failRequest(ctx, req, "")
	}

	switch txReq.Flag {
	case common.FlagProposeNormalTransaction:
	case common.FlagProposeRecoveryTransaction:
		if len(outputs) != 1 {
			logger.Printf("invalid recovery transaction outputs: %d", len(outputs))
			return node.failRequest(ctx, req, "")
		}

		balances, err := node.store.ReadAllSolanaTokenBalances(ctx, safe.Address)
		logger.Printf("store.ReadAllSolanaTokenBalances(%s) => %v %v", safe.Address, balances, err)
		if err != nil {
			panic(err)
		}

		for _, b := range balances {
			if b.AssetId == balance.AssetId || b.BigBalance().Cmp(big.NewInt(0)) == 0 {
				continue
			}

			output := &solana.Output{
				TokenAddress: b.AssetAddress,
				Destination:  sg.PublicKeyFromBytes(txReq.Extra[:]).String(),
				Amount:       b.BigBalance(),
			}
			outputs = append(outputs, output)

			asset, err := node.store.ReadAssetMeta(ctx, b.AssetId)
			logger.Printf("store.ReadAssetMeta(%s) => %v %v", b.AssetId, asset, err)
			if err != nil {
				panic(err)
			}

			amt := decimal.NewFromBigInt(output.Amount, int32(-asset.Decimals))
			r := map[string]string{
				"receiver": output.Destination,
				"amount":   amt.String(),
			}
			if output.TokenAddress != solana.SolanaEmptyAddress {
				r["token"] = output.TokenAddress
			}
			recipients = append(recipients, r)
		}
	default:
		logger.Printf("invalid transaction flag: %d", txReq.Flag)
		return node.failRequest(ctx, req, "")
	}

	voters := []sg.PublicKey{sg.MPK(safe.Holder), sg.MPK(safe.Holder), sg.MPK(safe.Signer)}
	t, err := solana.CreateTransactionFromOutputs(txReq, outputs, voters, sg.MPK(safe.Holder), uint32(safe.Nonce+1))
	logger.Printf("solana.CreateTransactionFromOutputs(%v) => %v %v", txReq, t, err)
	if err != nil {
		panic(err)
	}

	extra, err := t.MarshalBinary()
	logger.Printf("solana.Transaction.MarshalBinary(%v) => %v %v", t, extra, err)
	if err != nil {
		panic(err)
	}

	stx := node.buildStorageTransaction(ctx, req, []byte(common.Base91Encode(extra)))
	if stx == nil {
		return node.failRequest(ctx, req, "")
	}
	txs := []*mtg.Transaction{stx}

	typ := byte(common.ActionSolanaSafeProposeTransaction)
	crv := common.SafeChainCurve(safe.Chain)
	tt := node.buildObserverResponseWithStorageTraceId(ctx, req.Id, req.Output, typ, crv, stx.TraceId)
	if tt == nil {
		return node.failRequest(ctx, req, "")
	}
	txs = append(txs, tt)

	data := common.MarshalJSONOrPanic(recipients)
	tx := &store.Transaction{
		TransactionHash: t.Message.RecentBlockhash.String(),
		RawTransaction:  hex.EncodeToString(extra),
		Holder:          req.Holder,
		Chain:           safe.Chain,
		AssetId:         id.String(),
		State:           common.RequestStateInitial,
		Data:            string(data),
		RequestId:       req.Id,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	err = node.store.WriteTransactionWithRequest(ctx, tx, nil, txs, req)
	if err != nil {
		panic(err)
	}
	return txs, ""
}

func (node *Node) processSolanaSafeApproveTransaction(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}

	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err))
	}
	if safe == nil || safe.Chain != common.SafeChainSolana {
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
	t, err := sg.TransactionFromBytes(raw)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%x) => %v %v", raw, t, err)
	if err != nil {
		panic(err)
	}

	signed := solana.CheckTransactionSignedBy(t, sg.MPK(safe.Holder))
	logger.Printf("solana.CheckTransactionSignedBy(%v, %s) => %t", t, safe.Holder, signed)
	if !signed {
		return node.failRequest(ctx, req, "")
	}

	msg, err := t.Message.MarshalBinary()
	logger.Printf("solana.Transaction.MarshalBinary(%v) => %v %v", t, msg, err)
	if err != nil {
		panic(err)
	}

	sr := &store.SignatureRequest{
		TransactionHash: tx.TransactionHash,
		InputIndex:      0,
		Signer:          safe.Signer,
		Curve:           req.Curve,
		Message:         hex.EncodeToString(msg),
		State:           common.RequestStateInitial,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}

	sr.RequestId = common.UniqueId(req.Id, sr.Message)
	txs := node.buildSignerSignRequests(ctx, req, []*store.SignatureRequest{sr}, safe.Path)
	if len(txs) == 0 {
		return node.failRequest(ctx, req, "")
	}

	err = node.store.WriteSignatureRequestsWithRequest(ctx, []*store.SignatureRequest{sr}, tx.TransactionHash, hex.EncodeToString(raw), req, txs)
	logger.Printf("store.WriteSignatureRequestsWithRequest(%s, %d, %v) => %v", tx.TransactionHash, 1, req, err)
	if err != nil {
		panic(err)
	}
	return txs, ""
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
		msg := common.DecodeHexOrPanic(old.Message)
		if err := solana.VerifyMessageSignature(safe.Signer, msg, req.ExtraBytes()); err != nil {
			logger.Printf("solana.signer.Verify(%v) => %v", req, err)
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

	sig := sg.SignatureFromBytes(common.DecodeHexOrPanic(requests[0].Signature.String))
	if err := solana.AddSignature(t, sg.MPK(safe.Signer), sig); err != nil {
		panic(err)
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
