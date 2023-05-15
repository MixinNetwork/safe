package keeper

import (
	"context"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/domains/mvm"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/shopspring/decimal"
)

const (
	SafeChainBitcoin  = 1
	SafeChainEthereum = 2
	SafeChainMixin    = 3
	SafeChainMVM      = 4
	SafeChainLitecoin = 5

	SafeBitcoinChainId  = "c6d0c728-2624-429b-8e0d-d9d19b6592fa"
	SafeEthereumChainId = "43d61dcd-e413-450d-80b8-101d5e903357"
	SafeMVMChainId      = "a0ffd769-5850-4b48-9651-d2ae44a3e64d"
	SafeLitecoinChainId = "76c802a2-7c88-447f-a93e-c29c9e5dd9c8"

	SafeNetworkInfoTimeout = 3 * time.Minute
	SafeSignatureTimeout   = 10 * time.Minute
)

func (node *Node) refundAndFinishRequest(ctx context.Context, req *common.Request, receivers []string, threshold int) error {
	err := node.buildTransaction(ctx, req.AssetId, receivers, threshold, req.Amount.String(), nil, req.Id)
	if err != nil {
		return err
	}
	return node.store.FinishRequest(ctx, req.Id)
}

func (node *Node) bondMaxSupply(ctx context.Context, chain byte, assetId string) decimal.Decimal {
	switch assetId {
	case SafeBitcoinChainId:
		return decimal.RequireFromString("115792089237316195423570985008687907853269984665640564039457.58400791")
	default:
		panic(assetId)
	}
}

func (node *Node) getBondAsset(ctx context.Context, assetId, holder string) (crypto.Hash, byte, error) {
	asset, err := node.fetchAssetMeta(ctx, assetId)
	if err != nil {
		return crypto.Hash{}, 0, err
	}
	addr := abi.GetFactoryAssetAddress(assetId, asset.Symbol, asset.Name, holder)
	assetKey := strings.ToLower(addr.String())
	err = mvm.VerifyAssetKey(assetKey)
	if err != nil {
		return crypto.Hash{}, 0, err
	}
	return mvm.GenerateAssetId(assetKey), SafeChainMVM, nil
}
