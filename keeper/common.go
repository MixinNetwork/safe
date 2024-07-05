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

func (node *Node) failRequest(ctx context.Context, req *common.Request, assetId string) ([]*mtg.Transaction, string, error) {
	return nil, assetId, node.store.FailRequest(ctx, req.Id)
}

func (node *Node) refundAndFailRequest(ctx context.Context, req *common.Request, receivers []string, threshold int) ([]*mtg.Transaction, string, error) {
	logger.Printf("node.refundAndFailRequest(%v) => %v %d", req, receivers, threshold)
	t := node.buildTransaction(ctx, req.Sequence, node.conf.AppId, req.AssetId, receivers, threshold, req.Amount.String(), []byte("refund"), req.Id)
	if t == nil {
		return node.failRequest(ctx, req, req.AssetId)
	}
	return []*mtg.Transaction{t}, "", node.store.FailRequest(ctx, req.Id)
}

func (node *Node) bondMaxSupply(ctx context.Context, chain byte, assetId string) decimal.Decimal {
	switch assetId {
	case common.SafeBitcoinChainId, common.SafeLitecoinChainId, common.SafeEthereumChainId, common.SafeMVMChainId, common.SafePolygonChainId:
		return decimal.RequireFromString("115792089237316195423570985008687907853269984665640564039457.58400791")
	default:
		return decimal.RequireFromString("115792089237316195423570985008687907853269984665640564039457.58400791")
	}
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

func (node *Node) getBondAsset(ctx context.Context, entry, assetId, holder string) (crypto.Hash, string, byte, error) {
	asset, err := node.fetchAssetMeta(ctx, assetId)
	if err != nil {
		return crypto.Hash{}, "", 0, err
	}
	addr := abi.GetFactoryAssetAddress(entry, assetId, asset.Symbol, asset.Name, holder)
	assetKey := strings.ToLower(addr.String())
	err = ethereum.VerifyAssetKey(assetKey)
	if err != nil {
		return crypto.Hash{}, "", 0, err
	}
	safeAssetId := ethereum.GenerateAssetId(common.SafeChainPolygon, assetKey)
	return crypto.Sha256Hash([]byte(safeAssetId)), safeAssetId, common.SafeChainPolygon, nil
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
