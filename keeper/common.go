package keeper

import (
	"context"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
)

const (
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

func solanaDefaultDerivationPath() string {
	return "m/44'/501'/0'/0'"
}

func (node *Node) failRequest(ctx context.Context, req *common.Request, assetId string) ([]*mtg.Transaction, string) {
	logger.Printf("node.failRequest(%v, %s)", req, assetId)
	err := node.store.FailRequest(ctx, req, assetId, nil)
	if err != nil {
		panic(err)
	}
	return nil, assetId
}

func (node *Node) refundAndFailRequest(ctx context.Context, req *common.Request, receivers []string, threshold int) ([]*mtg.Transaction, string) {
	logger.Printf("node.refundAndFailRequest(%v) => %v %d", req, receivers, threshold)
	t := node.buildTransaction(ctx, req.Output, node.conf.AppId, req.AssetId, receivers, threshold, req.Amount.String(), []byte("refund"), req.Id)
	if t == nil {
		return node.failRequest(ctx, req, req.AssetId)
	}
	err := node.store.FailRequest(ctx, req, "", []*mtg.Transaction{t})
	if err != nil {
		panic(err)
	}
	return []*mtg.Transaction{t}, ""
}

func (node *Node) fetchBondAssetReceiver(ctx context.Context, address, assetId string) string {
	migrated, err := node.store.CheckMigrateAsset(ctx, address, assetId)
	if err != nil {
		panic(err)
	}

	if migrated {
		return node.conf.PolygonObserverDepositEntry
	}
	return node.conf.PolygonKeeperDepositEntry
}

func (node *Node) getBondAssetId(ctx context.Context, entry, assetId, holder string) string {
	asset, err := node.fetchAssetMeta(ctx, assetId)
	if err != nil {
		panic(err)
	}
	addr := abi.GetFactoryAssetAddress(entry, assetId, asset.Symbol, asset.Name, holder)
	assetKey := strings.ToLower(addr.String())
	err = ethereum.VerifyAssetKey(assetKey)
	if err != nil {
		panic(assetKey)
	}
	safeAssetId := ethereum.GenerateAssetId(common.SafeChainPolygon, assetKey)
	return safeAssetId
}

func (node *Node) verifySafeMessageSignatureWithHolderOrObserver(ctx context.Context, safe *store.Safe, ms string, sig []byte) error {
	switch common.NormalizeCurve(common.SafeChainCurve(safe.Chain)) {
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
