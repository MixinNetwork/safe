package computer

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"

	mc "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

type ReferencedTxAsset struct {
	Solana  bool
	Amount  decimal.Decimal
	Decimal int
	Address string
	AssetId string
	ChainId string
	Fee     bool
}

// should only return error when mtg could not find outputs from referenced transaction
// all assets needed in system call should be referenced
// extra amount of XIN is used for fees in system call like rent
func (node *Node) GetSystemCallReferenceTxs(ctx context.Context, requestHash string) ([]*store.SpentReference, *crypto.Hash, error) {
	var refs []*store.SpentReference
	req, err := node.store.ReadRequestByHash(ctx, requestHash)
	if err != nil || req == nil {
		panic(fmt.Errorf("store.ReadRequestByHash(%s) => %v %v", requestHash, req, err))
	}
	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, req.MixinHash.String())
	if err != nil || ver == nil {
		panic(fmt.Errorf("group.ReadKernelTransactionUntilSufficient(%s) => %v %v", req.MixinHash.String(), ver, err))
	}
	if common.CheckTestEnvironment(ctx) {
		ver.References = readOutputReferences(req.Id)
	}

	var storage *crypto.Hash
	for _, ref := range ver.References {
		rs, hash, err := node.getSystemCallReferenceTx(ctx, req, ref.String())
		if err != nil {
			return nil, nil, err
		}
		if len(rs) > 0 {
			refs = append(refs, rs...)
		}
		if hash != nil && storage == nil {
			storage = hash
		}
	}
	return refs, storage, nil
}

func (node *Node) getSystemCallReferenceTx(ctx context.Context, req *store.Request, hash string) ([]*store.SpentReference, *crypto.Hash, error) {
	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, hash)
	if err != nil || ver == nil {
		panic(fmt.Errorf("group.ReadKernelTransactionUntilSufficient(%s) => %v %v", hash, ver, err))
	}
	if common.CheckTestEnvironment(ctx) {
		value, err := node.store.ReadProperty(ctx, hash)
		if err != nil {
			panic(err)
		}
		if len(value) > 0 {
			extra, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				panic(err)
			}
			ver.Extra = extra
		}
	}
	// skip referenced storage transaction
	if ver.Asset.String() == common.XinKernelAssetId && len(ver.Extra) > mc.ExtraSizeGeneralLimit {
		h, _ := crypto.HashFromString(hash)
		return nil, &h, nil
	}
	outputs := node.group.ListOutputsByTransactionHash(ctx, hash, req.Sequence)
	if len(outputs) == 0 {
		return nil, nil, fmt.Errorf("unreceived reference %s", hash)
	}
	total := decimal.NewFromInt(0)
	for _, output := range outputs {
		total = total.Add(output.Amount)
	}
	asset, err := common.SafeReadAssetUntilSufficient(ctx, outputs[0].AssetId)
	if err != nil {
		panic(err)
	}
	refs := []*store.SpentReference{
		{
			TransactionHash: hash,
			RequestId:       req.Id,
			RequestHash:     req.MixinHash.String(),
			ChainId:         asset.ChainID,
			AssetId:         asset.AssetID,
			Amount:          total.String(),
			Asset:           asset,
		},
	}
	return refs, nil, nil
}

func (node *Node) GetSystemCallRelatedAsset(ctx context.Context, rs []*store.SpentReference) map[string]*ReferencedTxAsset {
	am := make(map[string]*ReferencedTxAsset)
	for _, ref := range rs {
		logger.Printf("node.GetReferencedTxAsset() => %v", ref)
		amt, err := decimal.NewFromString(ref.Amount)
		if err != nil {
			panic(err)
		}

		isSolAsset := ref.ChainId == solanaApp.SolanaChainBase
		address := ref.Asset.AssetKey
		if !isSolAsset {
			da, err := node.store.ReadDeployedAsset(ctx, ref.AssetId, common.RequestStateDone)
			if err != nil || da == nil {
				panic(fmt.Errorf("store.ReadDeployedAsset(%s) => %v %v", ref.AssetId, da, err))
			}
			address = da.Address
		}
		ra := &ReferencedTxAsset{
			Solana:  isSolAsset,
			Address: address,
			Decimal: ref.Asset.Precision,
			Amount:  amt,
			AssetId: ref.AssetId,
			ChainId: ref.Asset.ChainID,
			Fee:     ref.Fee,
		}
		if ra.Fee {
			am["fee"] = ra
			continue
		}
		old := am[ref.AssetId]
		if old != nil {
			ra.Amount = ra.Amount.Add(old.Amount)
		}
		am[ref.AssetId] = ra
	}
	for _, a := range am {
		logger.Printf("node.GetSystemCallRelatedAsset() => %v", a)
		if !a.Amount.IsPositive() {
			panic(a)
		}
	}
	return am
}

// should only return error when no valid fees found
func (node *Node) getSystemCallFeeFromXin(ctx context.Context, call *store.SystemCall) (*store.SpentReference, error) {
	req, err := node.store.ReadRequestByHash(ctx, call.RequestHash)
	if err != nil {
		panic(err)
	}
	extra := req.ExtraBytes()
	if len(extra) != 41 {
		return nil, nil
	}
	feeId := uuid.Must(uuid.FromBytes(extra[25:])).String()

	fee, err := node.store.ReadValidFeeInfo(ctx, feeId)
	if err != nil {
		panic(err)
	}
	if fee == nil {
		return nil, fmt.Errorf("invalid fee id: %s", feeId)
	}
	ratio, err := decimal.NewFromString(fee.Ratio)
	if err != nil {
		panic(err)
	}
	plan, err := node.store.ReadLatestOperationParams(ctx, req.CreatedAt)
	if err != nil {
		panic(err)
	}
	outputs := node.group.ListOutputsByTransactionHash(ctx, req.MixinHash.String(), req.Sequence)
	total := decimal.NewFromInt(0)
	for _, output := range outputs {
		total = total.Add(output.Amount)
	}
	if common.CheckTestEnvironment(ctx) {
		total = decimal.NewFromFloat(0.19461941 + 0.001)
	}
	if total.Compare(plan.OperationPriceAmount) == 0 {
		return nil, nil
	}
	feeOnXin := total.Sub(plan.OperationPriceAmount)
	feeOnSol := feeOnXin.Div(ratio).RoundCeil(8).String()

	asset, err := common.SafeReadAssetUntilSufficient(ctx, common.SafeSolanaChainId)
	if err != nil {
		panic(err)
	}

	return &store.SpentReference{
		TransactionHash: req.MixinHash.String(),
		RequestId:       req.Id,
		RequestHash:     req.MixinHash.String(),
		ChainId:         common.SafeSolanaChainId,
		AssetId:         common.SafeSolanaChainId,
		Amount:          feeOnSol,
		Asset:           asset,
		Fee:             true,
	}, nil
}

func (node *Node) getPostprocessCall(ctx context.Context, req *store.Request, call *store.SystemCall, data []byte) (*store.SystemCall, error) {
	if call.Type != store.CallTypeMain || len(data) == 0 {
		return nil, nil
	}

	postprocess, tx, err := node.getSubSystemCallFromExtra(ctx, req, data)
	if err != nil {
		return nil, err
	}
	postprocess.Superior = call.RequestId
	postprocess.Type = store.CallTypePostProcess
	postprocess.Public = call.Public
	postprocess.State = common.RequestStatePending

	user, err := node.store.ReadUser(ctx, call.UserIdFromPublicPath())
	if err != nil {
		panic(err)
	}
	if user == nil {
		return nil, fmt.Errorf("store.ReadUser(%s) => nil", call.UserIdFromPublicPath().String())
	}
	err = node.VerifySubSystemCall(ctx, tx, solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry), solana.MustPublicKeyFromBase58(user.ChainAddress))
	logger.Printf("node.VerifySubSystemCall(%s) => %v", user.ChainAddress, err)
	if err != nil {
		return nil, err
	}
	return postprocess, nil
}

func (node *Node) getSubSystemCallFromExtra(ctx context.Context, req *store.Request, data []byte) (*store.SystemCall, *solana.Transaction, error) {
	id, raw := uuid.Must(uuid.FromBytes(data[:16])).String(), data[16:]
	return node.buildSystemCallFromBytes(ctx, req, id, raw, true)
}

// should only return error when fail to parse nonce advance instruction;
// without fields of superior, type, public, skip_postprocess
func (node *Node) buildSystemCallFromBytes(ctx context.Context, req *store.Request, id string, raw []byte, withdrawn bool) (*store.SystemCall, *solana.Transaction, error) {
	tx, err := solana.TransactionFromBytes(raw)
	logger.Printf("solana.TransactionFromBytes(%x) => %v %v", raw, tx, err)
	if err != nil {
		return nil, nil, err
	}
	err = node.SolanaClient().ProcessTransactionWithAddressLookups(ctx, tx)
	if err != nil {
		panic(err)
	}
	advance, err := solanaApp.NonceAccountFromTx(tx)
	logger.Printf("solana.NonceAccountFromTx() => %v %v", advance, err)
	if err != nil {
		return nil, nil, err
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		panic(err)
	}
	call := &store.SystemCall{
		RequestId:       id,
		RequestHash:     req.MixinHash.String(),
		NonceAccount:    advance.GetNonceAccount().PublicKey.String(),
		Message:         hex.EncodeToString(msg),
		Raw:             tx.MustToBase64(),
		State:           common.RequestStateInitial,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
		RequestSignerAt: sql.NullTime{Valid: true, Time: req.CreatedAt},
	}
	if withdrawn {
		call.WithdrawalTraces = sql.NullString{Valid: true, String: ""}
		call.WithdrawnAt = sql.NullTime{Valid: true, Time: req.CreatedAt}
	}
	return call, tx, nil
}

func (node *Node) checkUserSystemCall(ctx context.Context, tx *solana.Transaction) error {
	if common.CheckTestEnvironment(ctx) {
		return nil
	}

	if !tx.IsSigner(node.SolanaPayer()) {
		return fmt.Errorf("tx.IsSigner(payer) => %t", false)
	}

	index := -1
	for i, acc := range tx.Message.AccountKeys {
		if !acc.Equals(node.SolanaPayer()) {
			continue
		}
		index = i
	}
	for i, ins := range tx.Message.Instructions {
		if i == 0 {
			continue
		}
		if slices.Contains(ins.Accounts, uint16(index)) {
			return fmt.Errorf("invalid instruction: %d %v", i, ins)
		}
	}
	return nil
}

func attachSystemCall(extra []byte, cid string, raw []byte) []byte {
	extra = append(extra, uuid.Must(uuid.FromString(cid)).Bytes()...)
	extra = append(extra, raw...)
	return extra
}
