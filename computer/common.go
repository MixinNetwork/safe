package computer

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/crypto"
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

func (node *Node) getSystemCallRelatedAsset(ctx context.Context, requestId string) map[string]*ReferencedTxAsset {
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

	as := make(map[string]*ReferencedTxAsset)
	for _, ref := range ver.References {
		refVer, err := node.group.ReadKernelTransactionUntilSufficient(ctx, ref.String())
		if err != nil {
			panic(fmt.Errorf("group.ReadKernelTransactionUntilSufficient(%s) => %v %v", ref.String(), refVer, err))
		}

		outputs := node.group.ListOutputsByTransactionHash(ctx, ref.String(), req.Sequence)
		if len(outputs) == 0 {
			continue
		}
		total := decimal.NewFromInt(0)
		for _, output := range outputs {
			total = total.Add(output.Amount)
		}

		asset, err := common.SafeReadAssetUntilSufficient(ctx, outputs[0].AssetId)
		if err != nil {
			panic(err)
		}
		ra := &ReferencedTxAsset{
			Solana: asset.ChainID == solanaApp.SolanaChainBase,
			Amount: total,
			Asset:  asset,
		}
		old := as[asset.AssetID]
		if old != nil {
			ra.Amount = ra.Amount.Add(old.Amount)
		}
		as[asset.AssetID] = ra
	}
	return as
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
