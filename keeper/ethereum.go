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
	logger.Printf("ethereum.UnmarshalSafeTransaction(%x) => %v %v", raw, t, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	signedByObserver, err := node.checkEthereumTransactionSignedBy(safe, t, safe.Observer)
	logger.Printf("node.checkEthereumTransactionSignedBy(%v, %s) => %t %v", t, safe.Observer, signedByObserver, err)
	if err != nil {
		return err
	} else if !signedByObserver {
		return node.store.FailRequest(ctx, req.Id)
	}
	if t.Destination.Hex() == safe.Address {
		return node.store.FailRequest(ctx, req.Id)
	}

	rpc, assetId := node.ethereumParams(safe.Chain)
	balance, err := node.store.ReadEthereumBalance(ctx, safe.Address, assetId)
	logger.Printf("store.ReadEthereumBalance(%s, %s) => %v %v", safe.Address, assetId, balance, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	if balance.Balance.Cmp(t.Value) != 0 {
		return fmt.Errorf("Inconsistent safe balance: %d %d", balance.Balance, t.Value.Uint64())
	}

	info, err := node.store.ReadLatestNetworkInfo(ctx, safe.Chain, req.CreatedAt)
	logger.Printf("store.ReadLatestNetworkInfo(%d) => %v %v", safe.Chain, info, err)
	if err != nil {
		return err
	}
	if info == nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	latest, err := ethereum.RPCGetBlock(rpc, info.Hash)
	logger.Printf("ethereum.RPCGetBlock(%s %s) => %v %v", rpc, info.Hash, latest, err)
	if err != nil {
		return err
	}
	transaction, err := ethereum.RPCGetTransactionByHash(rpc, balance.LatestTxHash)
	logger.Printf("ethereum.RPCGetTransactionByHash(%s %s) => %v %v", rpc, balance.LatestTxHash, transaction, err)
	if err != nil {
		return err
	}
	block, err := ethereum.RPCGetBlock(rpc, transaction.BlockHash)
	logger.Printf("ethereum.RPCGetBlock(%s %s) => %v %v", rpc, transaction.BlockHash, block, err)
	if err != nil {
		return err
	}
	if block.Time.IsZero() || latest.Time.IsZero() || block.Time.Add(safe.Timelock+1*time.Hour).After(latest.Time) {
		return fmt.Errorf("invalid timelock to close account %s %s", block.Time, latest.Time)
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
	if !bytes.Equal(t.Message, proposedTx.Message) {
		logger.Printf("Inconsistent safe tx message: %x %x", t.Message, proposedTx.Message)
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
	err = node.store.CloseAccountBySignatureRequestsWithRequest(ctx, []*store.SignatureRequest{sr}, tx.TransactionHash, req)
	logger.Printf("store.CloseAccountBySignatureRequestsWithRequest(%s, %v, %v) => %v", tx.TransactionHash, sr, req, err)
	if err != nil {
		return fmt.Errorf("store.WriteSignatureRequestsWithRequest(%s) => %v", tx.TransactionHash, err)
	}

	err = node.sendSignerSignRequest(ctx, sr, safe.Path)
	if err != nil {
		return fmt.Errorf("node.sendSignerSignRequest(%v) => %v", sr, err)
	}

	err = node.store.UpdateInitialTransaction(ctx, tx.TransactionHash, hex.EncodeToString(t.Marshal()))
	logger.Printf("store.UpdateInitialTransaction(%v) => %v", tx, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	return nil
}

func (node *Node) closeEthereumAccountWithHolder(ctx context.Context, req *common.Request, safe *store.Safe, raw []byte, receiver string) error {
	t, _ := ethereum.UnmarshalSafeTransaction(raw)
	signedByHolder, err := node.checkEthereumTransactionSignedBy(safe, t, safe.Holder)
	logger.Printf("node.checkEthereumTransactionSignedBy(%v, %s) => %t %v", t, safe.Holder, signedByHolder, err)
	if err != nil {
		return err
	} else if !signedByHolder {
		return node.store.FailRequest(ctx, req.Id)
	}

	amt := decimal.New(t.Value.Int64(), -ethereum.ValuePrecision)
	data := common.MarshalJSONOrPanic([]map[string]string{{
		"receiver": receiver,
		"amount":   amt.String(),
	}})
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
		panic(err)
	}
	tx, err := node.store.ReadTransaction(ctx, gs.TxHash)
	logger.Printf("store.ReadTransaction(%s) => %v %v", gs.TxHash, tx, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
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
		return node.store.FailRequest(ctx, req.Id)
	}
	_, pubs := ethereum.GetSortedSafeOwners(sp.Holder, sp.Signer, sp.Observer)
	logger.Printf("ethereum.GetSortedSafeOwners(%s, %s, %s) => %v", sp.Holder, sp.Signer, sp.Observer, pubs)
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
		Nonce:     0,
		CreatedAt: req.CreatedAt,
		UpdatedAt: req.CreatedAt,
	}
	err = node.store.WriteUnfinishedSafe(ctx, safe)
	logger.Printf("store.WriteUnfinishedSafe(%v) => %v", safe, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
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
		for _, rp := range recipients {
			amt, err := decimal.NewFromString(rp[1])
			if err != nil {
				return node.store.FailRequest(ctx, req.Id)
			}
			if amt.Cmp(plan.TransactionMinimum) < 0 {
				return node.store.FailRequest(ctx, req.Id)
			}
			outputs = append(outputs, &ethereum.Output{
				Destination: rp[0],
				Amount:      ethereum.ParseWei(amt.String()),
			})
		}
	} else {
		outputs = []*ethereum.Output{{
			Destination: string(extra[16:]),
			Amount:      ethereum.ParseWei(req.Amount.String()),
		}}
	}

	total := decimal.Zero
	recipients := make([]map[string]string, len(outputs))
	for i, out := range outputs {
		norm := ethereum.NormalizeAddress(out.Destination)
		if norm == "" || norm == safe.Address {
			return node.store.FailRequest(ctx, req.Id)
		}
		amt := decimal.NewFromBigInt(out.Amount, -ethereum.ValuePrecision)
		recipients[i] = map[string]string{
			"receiver": out.Destination, "amount": amt.String(),
		}
		total = total.Add(amt)
	}
	if !total.Equal(req.Amount) {
		return node.store.FailRequest(ctx, req.Id)
	}

	chainId := ethereum.GetEvmChainID(int64(safe.Chain))
	_, assetId = node.ethereumParams(safe.Chain)
	txType := ethereum.TypeETHTx
	t, err := ethereum.CreateTransactionFromOutputs(ctx, txType, chainId, req.Id, safe.Address, outputs, big.NewInt(safe.Nonce))
	logger.Printf("ethereum.CreateTransactionFromOutputs(%d, %d, %s, %s, %v, %d) => %v %v",
		txType, chainId, req.Id, safe.Address, outputs, safe.Nonce, t, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	balance, err := node.store.ReadEthereumBalance(ctx, safe.Address, assetId)
	logger.Printf("store.ReadEthereumBalance(%s, %s) => %v %v", safe.Address, assetId, balance, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	if t.Value.Cmp(balance.Balance) > 0 {
		logger.Printf("insufficient balance %s %s", t.Value.String(), balance.Balance.String())
		return node.store.FailRequest(ctx, req.Id)
	}

	extra = t.Marshal()
	exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(extra)))
	typ := byte(common.ActionEthereumSafeProposeTransaction)
	crv := SafeChainCurve(safe.Chain)
	err = node.sendObserverResponseWithReferences(ctx, req.Id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", req.Id, exk, err)
	}

	data := common.MarshalJSONOrPanic(recipients)
	tx := &store.Transaction{
		TransactionHash: t.TxHash,
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
	logger.Printf("ethereum.UnmarshalSafeTransaction(%x) => %v %v", raw, t, err)
	if err != nil {
		panic(err)
	}

	signed, err := node.checkEthereumTransactionSignedBy(safe, t, safe.Holder)
	logger.Printf("node.checkEthereumTransactionSignedBy(%v, %s) => %t %v", t, safe.Holder, signed, err)
	if err != nil {
		return err
	} else if !signed {
		return node.store.FailRequest(ctx, req.Id)
	}

	err = node.store.UpdateInitialTransaction(ctx, tx.TransactionHash, hex.EncodeToString(t.Marshal()))
	logger.Printf("store.UpdateInitialTransaction(%v) => %v", tx, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
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

func (node *Node) processEthereumSafeSignatureResponse(ctx context.Context, req *common.Request, safe *store.Safe, tx *store.Transaction, old *store.SignatureRequest) error {
	if req.Role != common.RequestRoleSigner {
		panic(req.Role)
	}

	sig, _ := hex.DecodeString(req.Extra)
	msg := common.DecodeHexOrPanic(old.Message)
	err := ethereum.VerifyHashSignature(safe.Signer, msg, sig)
	logger.Printf("node.VerifyHashSignature(%v) => %v", req, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	err = node.store.FinishSignatureRequest(ctx, req)
	logger.Printf("store.FinishSignatureRequest(%s) => %v", req.Id, err)
	if err != nil {
		return fmt.Errorf("store.FinishSignatureRequest(%s) => %v", req.Id, err)
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
		return fmt.Errorf("store.ListAllSignaturesForTransaction(%s) => %v", old.TransactionHash, err)
	}
	if len(requests) != 1 {
		return fmt.Errorf("Invalid signature requests len: %d", len(requests))
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

	_, assetId := node.ethereumParams(safe.Chain)
	balance, err := node.store.ReadEthereumBalance(ctx, safe.Address, assetId)
	logger.Printf("store.ReadEthereumBalance(%s, %s) => %v %v", safe.Address, assetId, balance, err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}
	closeBalance := balance.Balance.Sub(balance.Balance, t.Value)
	if closeBalance.Cmp(big.NewInt(0)) < 0 {
		logger.Printf("safe %s close balance %d lower than 0", safe.Address, closeBalance)
		return node.store.FailRequest(ctx, req.Id)
	}
	err = node.store.CreateOrUpdateEthereumBalanceWithCloseBalance(ctx, safe, closeBalance, assetId)
	logger.Printf("store.CreateOrUpdateEthereumBalanceWithCloseBalance(%s, %s, %s) => %v", safe.Address, assetId, closeBalance.String(), err)
	if err != nil {
		return node.store.FailRequest(ctx, req.Id)
	}

	if safe.State == common.RequestStatePending {
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
		id := common.UniqueId(req.Id, safe.Address)
		err = node.sendObserverResponseWithAssetAndReferences(ctx, id, typ, crv, spr.AssetId, spr.Amount.String(), exk)
		if err != nil {
			return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", req.Id, exk, err)
		}

		chainId := ethereum.GetEvmChainID(int64(sp.Chain))
		gt, err := ethereum.CreateTransaction(ctx, ethereum.TypeInitGuardTx, chainId, sp.RequestId, sp.Address, sp.Address, "", "0", new(big.Int).SetUint64(0))
		if err != nil {
			return err
		}
		if !bytes.Equal(gt.Data, t.Data) {
			return fmt.Errorf("invalid safe guard transaction %x %x", gt.Data, t.Data)
		}

		return node.store.FinishSafeWithRequest(ctx, old.TransactionHash, raw, req, safe)
	}

	exk := node.writeStorageOrPanic(ctx, []byte(common.Base91Encode(t.Marshal())))
	id := common.UniqueId(old.TransactionHash, hex.EncodeToString(exk[:]))
	typ := byte(common.ActionEthereumSafeApproveTransaction)
	crv := SafeChainCurve(safe.Chain)
	err = node.sendObserverResponseWithReferences(ctx, id, typ, crv, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", id, exk, err)
	}

	err = node.store.FinishTransactionSignaturesWithRequest(ctx, old.TransactionHash, raw, req, 0, safe)
	logger.Printf("store.FinishTransactionSignaturesWithRequest(%s, %s, %v) => %v", old.TransactionHash, raw, req, err)
	return err
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
