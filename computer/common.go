package computer

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	mc "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

type ReferencedTxAsset struct {
	Solana bool
	Amount decimal.Decimal
	Asset  *bot.AssetNetwork
}

func (node *Node) GetSystemCallReferenceTxs(ctx context.Context, requestId string) ([]*store.SpentReference, error) {
	var refs []*store.SpentReference
	req, err := node.store.ReadRequest(ctx, requestId)
	if err != nil || req == nil {
		panic(fmt.Errorf("store.ReadRequest(%s) => %v %v", requestId, req, err))
	}
	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, req.MixinHash.String())
	if err != nil || ver == nil {
		panic(fmt.Errorf("group.ReadKernelTransactionUntilSufficient(%s) => %v %v", req.MixinHash.String(), ver, err))
	}
	if common.CheckTestEnvironment(ctx) {
		h1, _ := crypto.HashFromString("a8eed784060b200ea7f417309b12a33ced8344c24f5cdbe0237b7fc06125f459")
		h2, _ := crypto.HashFromString("01c43005fd06e0b8f06a0af04faf7530331603e352a11032afd0fd9dbd84e8ee")
		ver.References = []crypto.Hash{h1, h2}
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
	if total.Compare(plan.OperationPriceAmount) == 1 {
		amount := total.Sub(plan.OperationPriceAmount)
		asset, err := common.SafeReadAssetUntilSufficient(ctx, req.AssetId)
		if err != nil {
			panic(err)
		}
		refs = append(refs, &store.SpentReference{
			TransactionHash: req.MixinHash.String(),
			RequestId:       req.Id,
			ChainId:         bot.EthereumChainId,
			AssetId:         bot.XINAssetId,
			Amount:          amount.String(),
			Asset:           asset,
		})
	}

	for _, ref := range ver.References {
		rs, err := node.getSystemCallReferenceTx(ctx, req, ref.String())
		if err != nil {
			return nil, err
		}
		if len(rs) > 0 {
			refs = append(refs, rs...)
		}
	}
	return refs, nil
}

func (node *Node) getSystemCallReferenceTx(ctx context.Context, req *store.Request, hash string) ([]*store.SpentReference, error) {
	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, hash)
	if err != nil || ver == nil {
		panic(fmt.Errorf("group.ReadKernelTransactionUntilSufficient(%s) => %v %v", hash, ver, err))
	}
	if ver.Asset.String() == "a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc" && len(ver.Extra) > mc.ExtraSizeGeneralLimit {
		return nil, nil
	}
	outputs := node.group.ListOutputsByTransactionHash(ctx, hash, req.Sequence)
	if len(outputs) == 0 {
		return nil, fmt.Errorf("unreceived reference %s", hash)
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
			ChainId:         asset.ChainID,
			AssetId:         asset.AssetID,
			Amount:          total.String(),
			Asset:           asset,
		},
	}

	for _, ref := range ver.References {
		rs, err := node.getSystemCallReferenceTx(ctx, req, ref.String())
		if err != nil {
			return nil, err
		}
		if len(rs) > 0 {
			refs = append(refs, rs...)
		}
	}
	return refs, nil
}

func (node *Node) GetSystemCallRelatedAsset(ctx context.Context, rs []*store.SpentReference) map[string]*ReferencedTxAsset {
	am := make(map[string]*ReferencedTxAsset)
	for _, ref := range rs {
		logger.Printf("node.GetReferencedTxAsset() => %v", ref)
		amt, err := decimal.NewFromString(ref.Amount)
		if err != nil {
			panic(err)
		}

		ra := &ReferencedTxAsset{
			Solana: ref.ChainId == solanaApp.SolanaChainBase,
			Amount: amt,
			Asset:  ref.Asset,
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

func (node *Node) processSetOperationParams(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeSetOperationParams {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	if len(extra) != 24 {
		return node.failRequest(ctx, req, "")
	}

	assetId := uuid.Must(uuid.FromBytes(extra[:16]))
	abu := new(big.Int).SetUint64(binary.BigEndian.Uint64(extra[16:24]))
	amount := decimal.NewFromBigInt(abu, -8)
	params := &store.OperationParams{
		RequestId:            req.Id,
		OperationPriceAsset:  assetId.String(),
		OperationPriceAmount: amount,
		CreatedAt:            req.CreatedAt,
	}
	err := node.store.WriteOperationParamsFromRequest(ctx, params, req)
	if err != nil {
		panic(err)
	}
	return nil, ""
}
