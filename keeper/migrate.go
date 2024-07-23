package keeper

import (
	"context"
	"fmt"
	"slices"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	gc "github.com/ethereum/go-ethereum/common"
	"github.com/gofrs/uuid/v5"
)

const FinalRequestHash = "373a88f0ac8f2330cc8b92be3b54c2f2fe388fa13aa5591bd11f298547dc89ac"

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
	logger.Printf("keeper.Migrate() ...")
	req, err := node.store.ReadUnmigratedLatestRequest(ctx)
	if err != nil || req == nil {
		return fmt.Errorf("store.ReadUnmigratedLatestRequest() => %v %v", req, err)
	}
	if req.MixinHash.String() != FinalRequestHash {
		return fmt.Errorf("invalid final request hash: %s", req.MixinHash.String())
	}
	logger.Printf("keeper.Migrate() => %v", req)

	safes, err := node.store.ListUnmigratedSafesWithState(ctx)
	if err != nil {
		return err
	}
	logger.Printf("keeper.Migrate() => unmigrated safes %d", len(safes))

	var ss, es []*store.MigrateAsset
	for _, safe := range safes {
		chainAssetId := common.SafeChainAssetId(safe.Chain)
		ma, err := node.getMigrateAsset(ctx, safe, chainAssetId)
		if err != nil {
			return err
		}
		ss = append(ss, ma)
		switch safe.Chain {
		case common.SafeChainEthereum, common.SafeChainPolygon:
			bs, err := node.store.ReadUnmigratedEthereumAllBalance(ctx, safe.Address)
			if err != nil {
				return err
			}
			for _, balance := range bs {
				ma, err := node.getMigrateAsset(ctx, safe, balance.AssetId)
				if err != nil {
					return err
				}
				es = append(es, ma)
			}
		}
	}
	logger.Printf("keeper.Migrate() => unmigrated assets %d %d", len(ss), len(es))

	err = node.store.Migrate(ctx, ss, es)
	logger.Printf("keeper.Migrate() => %v", err)
	return err
}

func (node *Node) checkSafeTokenMigration(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	meta, err := node.fetchAssetMeta(ctx, req.AssetId)
	if err != nil {
		panic(fmt.Errorf("node.fetchAssetMeta(%s) => %v", req.AssetId, err))
	}
	if meta.Chain != common.SafeChainPolygon {
		logger.Printf("invalid meta asset chain: %d", meta.Chain)
		return node.failRequest(ctx, req, "")
	}
	deployed, err := abi.CheckFactoryAssetDeployed(node.conf.PolygonRPC, meta.AssetKey)
	logger.Printf("abi.CheckFactoryAssetDeployed(%s) => %v %v", meta.AssetKey, deployed, err)
	if err != nil {
		panic(fmt.Errorf("abi.CheckFactoryAssetDeployed(%s) => %v", meta.AssetKey, err))
	}
	if deployed.Sign() <= 0 {
		return node.failRequest(ctx, req, "")
	}

	id := uuid.Must(uuid.FromBytes(deployed.Bytes()))
	_, err = node.fetchAssetMeta(ctx, id.String())
	if err != nil {
		panic(fmt.Errorf("node.fetchAssetMeta(%s) => %v", id, err))
	}

	extra := req.ExtraBytes()
	if len(extra) != 20 {
		return node.failRequest(ctx, req, "")
	}
	receiver := gc.BytesToAddress(extra).String()
	if receiver != node.conf.PolygonObserverDepositEntry {
		panic(receiver)
	}

	safe, err := node.store.ReadSafe(ctx, req.Holder)
	logger.Printf("store.ReadSafe(%s) => %v %v", req.Holder, safe, err)
	if err != nil {
		panic(err)
	}
	if safe == nil || safe.State != common.RequestStateDone {
		return node.failRequest(ctx, req, "")
	}
	switch safe.Chain {
	case common.SafeChainBitcoin, common.SafeChainLitecoin:
		if safe.SafeAssetId != req.AssetId {
			panic(req.AssetId)
		}
	case common.SafeChainEthereum, common.SafeChainPolygon:
		bs, err := node.store.ReadAllEthereumTokenBalances(ctx, safe.Address)
		if err != nil {
			panic(err)
		}
		found := slices.IndexFunc(bs, func(sb *store.SafeBalance) bool {
			return sb.SafeAssetId == req.AssetId
		})
		if found < 0 && req.AssetId != safe.SafeAssetId {
			panic(req.AssetId)
		}
	}

	return node.failRequest(ctx, req, "")
}
