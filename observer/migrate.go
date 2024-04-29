package observer

import (
	"context"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
)

func (node *Node) migrate(ctx context.Context) error {
	safes, err := node.keeperStore.ListSafesWithState(ctx, common.RequestStateDone)
	if err != nil {
		return err
	}

	for _, safe := range safes {
		switch safe.Chain {
		case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
			_, assetId := node.bitcoinParams(safe.Chain)
			_, err := node.checkOrDeployKeeperBond(ctx, safe.Chain, assetId, "", safe.Holder)
			if err != nil {
				return err
			}
		case keeper.SafeChainEthereum, keeper.SafeChainPolygon:
			balances, err := node.keeperStore.ReadEthereumAllBalance(ctx, safe.Address)
			if err != nil {
				return err
			}
			for _, balance := range balances {
				_, err = node.checkOrDeployKeeperBond(ctx, safe.Chain, balance.AssetId, balance.AssetAddress, safe.Holder)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}
