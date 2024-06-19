package keeper

import (
	"context"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/shopspring/decimal"
)

const (
	SafeChainBitcoin  = bitcoin.ChainBitcoin
	SafeChainLitecoin = bitcoin.ChainLitecoin
	SafeChainEthereum = ethereum.ChainEthereum
	SafeChainMVM      = ethereum.ChainMVM
	SafeChainPolygon  = ethereum.ChainPolygon

	SafeBitcoinChainId  = "c6d0c728-2624-429b-8e0d-d9d19b6592fa"
	SafeEthereumChainId = "43d61dcd-e413-450d-80b8-101d5e903357"
	SafeMVMChainId      = "a0ffd769-5850-4b48-9651-d2ae44a3e64d"
	SafeLitecoinChainId = "76c802a2-7c88-447f-a93e-c29c9e5dd9c8"
	SafePolygonChainId  = "b7938396-3f94-4e0a-9179-d3440718156f"

	SafeSignatureTimeout  = 10 * time.Minute
	SafeKeyBackupMaturity = 24 * time.Hour

	SafeStateApproved = common.RequestStateDone
	SafeStatePending  = common.RequestStatePending
	SafeStateClosed   = common.RequestStateFailed
)

func bitcoinDefaultDerivationPath() []byte {
	return []byte{2, 0, 0, 0}
}

func ethereumDefaultDerivationPath() []byte {
	return []byte{0, 0, 0, 0}
}

func SafeCurveChain(crv byte) byte {
	switch crv {
	case common.CurveSecp256k1ECDSABitcoin:
		return SafeChainBitcoin
	case common.CurveSecp256k1ECDSALitecoin:
		return SafeChainLitecoin
	case common.CurveSecp256k1ECDSAEthereum:
		return SafeChainEthereum
	case common.CurveSecp256k1ECDSAMVM:
		return SafeChainMVM
	case common.CurveSecp256k1ECDSAPolygon:
		return SafeChainPolygon
	default:
		panic(crv)
	}
}

func SafeChainCurve(chain byte) byte {
	switch chain {
	case SafeChainBitcoin:
		return common.CurveSecp256k1ECDSABitcoin
	case SafeChainLitecoin:
		return common.CurveSecp256k1ECDSALitecoin
	case SafeChainEthereum:
		return common.CurveSecp256k1ECDSAEthereum
	case SafeChainMVM:
		return common.CurveSecp256k1ECDSAMVM
	case SafeChainPolygon:
		return common.CurveSecp256k1ECDSAPolygon
	default:
		panic(chain)
	}
}

func (node *Node) refundAndFailRequest(ctx context.Context, req *common.Request, receivers []string, threshold int) ([]*mtg.Transaction, string, error) {
	logger.Printf("node.refundAndFailRequest(%v) => %v %d", req, receivers, threshold)
	t, asset, err := node.buildTransaction(ctx, req.Sequence, node.conf.AppId, req.AssetId, receivers, threshold, req.Amount.String(), []byte("refund"), req.Id)
	if err != nil || asset != "" {
		logger.Printf("node.buildTransaction(%v) => %v %s %v", req, t, asset, err)
		return nil, asset, err
	}
	return []*mtg.Transaction{t}, "", node.store.FailRequest(ctx, req.Id)
}

func (node *Node) bondMaxSupply(ctx context.Context, chain byte, assetId string) decimal.Decimal {
	switch assetId {
	case SafeBitcoinChainId, SafeLitecoinChainId, SafeEthereumChainId, SafeMVMChainId, SafePolygonChainId:
		return decimal.RequireFromString("115792089237316195423570985008687907853269984665640564039457.58400791")
	default:
		return decimal.RequireFromString("115792089237316195423570985008687907853269984665640564039457.58400791")
	}
}

func (node *Node) getBondAsset(ctx context.Context, assetId, holder string) (crypto.Hash, byte, error) {
	entry := node.conf.PolygonGroupEntry
	safe, err := node.store.ReadSafe(ctx, holder)
	if err != nil {
		return crypto.Hash{}, 0, err
	}
	if safe != nil {
		if safe.Receiver != "" {
			entry = safe.Receiver
		}
		switch safe.Chain {
		case SafeChainBitcoin, SafeChainLitecoin:
		case SafeChainEthereum, SafeChainPolygon, SafeChainMVM:
			migrated, err := node.store.CheckEthereumAssetMigrated(ctx, safe.Address, assetId)
			if err != nil {
				return crypto.Hash{}, 0, err
			}
			if !migrated {
				entry = node.conf.PolygonGroupEntry
			}
		}
	}
	if common.CheckTestEnvironment(ctx) && assetId == "218bc6f4-7927-3f8e-8568-3a3725b74361" {
		entry = node.conf.PolygonGroupEntry
	}

	asset, err := node.fetchAssetMeta(ctx, assetId)
	if err != nil {
		return crypto.Hash{}, 0, err
	}
	addr := abi.GetFactoryAssetAddress(entry, assetId, asset.Symbol, asset.Name, holder)
	assetKey := strings.ToLower(addr.String())
	err = ethereum.VerifyAssetKey(assetKey)
	if err != nil {
		return crypto.Hash{}, 0, err
	}
	return crypto.Sha256Hash([]byte(ethereum.GenerateAssetId(SafeChainPolygon, assetKey))), SafeChainPolygon, nil
}

func (node *Node) verifySafeMessageSignatureWithHolderOrObserver(ctx context.Context, safe *store.Safe, ms string, sig []byte) error {
	switch common.NormalizeCurve(SafeChainCurve(safe.Chain)) {
	case common.CurveSecp256k1ECDSABitcoin:
		msg := bitcoin.HashMessageForSignature(ms, safe.Chain)
		err := bitcoin.VerifySignatureDER(safe.Holder, msg, sig)
		logger.Printf("holder: bitcoin.VerifySignatureDER(%s, %x) => %v", ms, sig, err)
		if err != nil {
			odk, err := node.deriveBIP32WithPath(ctx, safe.Observer, common.DecodeHexOrPanic(safe.Path))
			if err != nil {
				return err
			}
			err = bitcoin.VerifySignatureDER(odk, msg, sig)
			logger.Printf("holder: bitcoin.VerifySignatureDER(%s, %x) => %v", ms, sig, err)
			if err != nil {
				return err
			}
		}
	case common.CurveSecp256k1ECDSAEthereum:
		msg := []byte(ms)
		err := ethereum.VerifyMessageSignature(safe.Holder, msg, sig)
		logger.Printf("holder: ethereum.VerifyMessageSignature(%s, %x) => %v", ms, sig, err)
		if err != nil {
			err = ethereum.VerifyMessageSignature(safe.Observer, msg, sig)
			logger.Printf("observer: ethereum.VerifyMessageSignature(%s, %x) => %v", ms, sig, err)
			if err != nil {
				return err
			}
		}
	default:
		panic(safe.Chain)
	}
	return nil
}
