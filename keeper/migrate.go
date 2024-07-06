package keeper

import (
	"context"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
)

func (node *Node) getMigrateAsset(ctx context.Context, safe *store.Safe, assetId string) (*store.MigrateAsset, error) {
	safeAssetId := node.getBondAssetId(ctx, node.conf.PolygonObserverDepositEntry, assetId, safe.Holder)
	return &store.MigrateAsset{
		Chain:       safe.Chain,
		Address:     safe.Address,
		AssetId:     assetId,
		SafeAssetId: safeAssetId,
	}, nil
}

func (node *Node) Migrate(ctx context.Context) error {
	// FIXME ensure the latest request id is correct before migration
	safes, err := node.store.ListUnmigratedSafesWithState(ctx)
	if err != nil {
		return err
	}

	var ms []*store.MigrateAsset
	for _, safe := range safes {
		chainAssetId := common.SafeChainAssetId(safe.Chain)
		ma, err := node.getMigrateAsset(ctx, safe, chainAssetId)
		if err != nil {
			return err
		}
		ms = append(ms, ma)

		switch safe.Chain {
		case common.SafeChainEthereum, common.SafeChainMVM, common.SafeChainPolygon:
			bs, err := node.store.ReadAllEthereumTokenBalances(ctx, safe.Address)
			if err != nil {
				return err
			}
			for _, balance := range bs {
				if balance.AssetId == chainAssetId {
					continue
				}
				ma, err := node.getMigrateAsset(ctx, safe, balance.AssetId)
				if err != nil {
					return err
				}
				ms = append(ms, ma)
			}
		}
	}

	return node.store.Migrate(ctx, ms)
}
