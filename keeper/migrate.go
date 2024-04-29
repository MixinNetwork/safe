package keeper

import (
	"context"
	"slices"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/shopspring/decimal"
)

func (node *Node) fetchBond(ctx context.Context, assetId, holder string) (*store.Asset, error) {
	bondId, _, err := node.getBondAsset(ctx, assetId, holder)
	if err != nil {
		return nil, err
	}
	bond, err := node.fetchAssetMeta(ctx, bondId.String())
	return bond, err
}

func (node *Node) sendBondAsset(ctx context.Context, bond *store.Asset, safe *store.Safe, amount decimal.Decimal) error {
	os, err := node.mixin.SafeListUtxos(ctx, mixin.SafeListUtxoOption{
		Members:   node.group.GetMembers(),
		Threshold: uint8(node.group.GetThreshold()),
		Asset:     bond.AssetId,
	})
	if err != nil {
		return err
	}
	if len(os) == 0 {
		panic(bond.AssetId)
	}

	for _, o := range os {
		if o.State == mixin.SafeUtxoStateSpent || slices.Contains(o.Signers, node.mixin.ClientID) {
			return nil
		}
	}

	traceId := common.UniqueId(safe.Holder, bond.AssetId)
	_, err = common.SendTransactionUntilSufficient(ctx, node.mixin, node.group.GetMembers(), node.group.GetThreshold(), safe.Receivers, int(safe.Threshold), amount, traceId, bond.AssetId, "", node.conf.MTG.App.SpendPrivateKey)
	return err
}

func (node *Node) checkBondAssetDeploymentAndSend(ctx context.Context, safes []*store.Safe) error {
	filter := make(map[string]bool)

	for {
		allHandled := true
		for _, safe := range safes {
			if filter[safe.Address] {
				continue
			}
			allHandled = false

			switch safe.Chain {
			case SafeChainBitcoin, SafeChainLitecoin:
				_, assetId := node.bitcoinParams(safe.Chain)
				bond, err := node.fetchBond(ctx, assetId, safe.Holder)
				if err != nil || bond == nil {
					return err
				}

				utxos, err := node.store.ListAllBitcoinUTXOsForHolder(ctx, safe.Holder)
				if err != nil {
					return err
				}
				if len(utxos) > 0 {
					var total int64
					for _, o := range utxos {
						total += o.Satoshi
					}
					amt := decimal.NewFromInt(total).Div(decimal.New(1, bitcoin.ValuePrecision))
					err = node.sendBondAsset(ctx, bond, safe, amt)
					if err != nil {
						return err
					}
				}

			case SafeChainEthereum, SafeChainPolygon:
				balances, err := node.store.ReadEthereumAllBalance(ctx, safe.Address)
				if err != nil {
					return err
				}

				flag := true
				for _, balance := range balances {
					bond, err := node.fetchBond(ctx, balance.AssetId, safe.Holder)
					if err != nil {
						return err
					}
					if bond == nil {
						flag = false
						continue
					}
					amt := decimal.NewFromBigInt(balance.Balance, int32(-bond.Decimals))

					err = node.sendBondAsset(ctx, bond, safe, amt)
					if err != nil {
						return err
					}
				}
				if !flag {
					continue
				}
			}

			filter[safe.Address] = true
		}

		if allHandled {
			return nil
		}
	}
}

func (node *Node) migrate(ctx context.Context) error {
	safes, err := node.store.ListSafesWithState(ctx, common.RequestStateDone)
	if err != nil {
		return err
	}

	err = node.checkBondAssetDeploymentAndSend(ctx, safes)
	if err != nil {
		return err
	}

	return nil
}
