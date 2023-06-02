package keeper

import (
	"context"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/domains/mvm"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/shopspring/decimal"
)

const (
	SafeChainBitcoin  = bitcoin.ChainBitcoin
	SafeChainEthereum = 2
	SafeChainMixin    = 3
	SafeChainMVM      = 4
	SafeChainLitecoin = bitcoin.ChainLitecoin

	SafeBitcoinChainId  = "c6d0c728-2624-429b-8e0d-d9d19b6592fa"
	SafeEthereumChainId = "43d61dcd-e413-450d-80b8-101d5e903357"
	SafeMVMChainId      = "a0ffd769-5850-4b48-9651-d2ae44a3e64d"
	SafeLitecoinChainId = "76c802a2-7c88-447f-a93e-c29c9e5dd9c8"

	SafeNetworkInfoTimeout = 3 * time.Minute
	SafeSignatureTimeout   = 10 * time.Minute
	SafeKeyBackupMaturity  = 24 * time.Hour
)

func bitcoinCurveChain(crv byte) byte {
	switch crv {
	case common.CurveSecp256k1ECDSABitcoin:
		return SafeChainBitcoin
	case common.CurveSecp256k1ECDSALitecoin:
		return SafeChainLitecoin
	default:
		panic(crv)
	}
}

func bitcoinChainCurve(chain byte) byte {
	switch chain {
	case SafeChainBitcoin:
		return common.CurveSecp256k1ECDSABitcoin
	case SafeChainLitecoin:
		return common.CurveSecp256k1ECDSALitecoin
	default:
		panic(chain)
	}
}

func (node *Node) refundAndFailRequest(ctx context.Context, req *common.Request, receivers []string, threshold int) error {
	logger.Printf("node.refundAndFailRequest(%s) => %v %d", req, receivers, threshold)
	err := node.buildTransaction(ctx, req.AssetId, receivers, threshold, req.Amount.String(), nil, req.Id)
	if err != nil {
		return err
	}
	return node.store.FailRequest(ctx, req.Id)
}

func (node *Node) bondMaxSupply(ctx context.Context, chain byte, assetId string) decimal.Decimal {
	switch assetId {
	case SafeBitcoinChainId, SafeLitecoinChainId:
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
