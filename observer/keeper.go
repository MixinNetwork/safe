package observer

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/shopspring/decimal"
)

func (node *Node) deriveBIP32WithKeeperPath(ctx context.Context, public, path string) (string, error) {
	path8, err := hex.DecodeString(path)
	if err != nil || len(path8) != 4 || path8[0] > 3 {
		return "", fmt.Errorf("invalid keeper derivation path: %s", path)
	}
	path32 := make([]uint32, path8[0])
	for i := range path8[0] {
		path32[i] = uint32(path8[1+i])
	}
	sk, err := node.keeperStore.ReadKey(ctx, public)
	if err != nil || sk == nil {
		return "", fmt.Errorf("keeperStore.ReadKey(%s) => %v %v", public, sk, err)
	}
	code, err := hex.DecodeString(sk.Extra)
	if err != nil {
		return "", err
	}
	_, sdk, err := bitcoin.DeriveBIP32(public, code, path32...)
	return sdk, err
}

func (node *Node) sendKeeperResponse(ctx context.Context, holder string, typ, chain uint8, id string, extra []byte) error {
	return node.sendKeeperResponseWithReferences(ctx, holder, typ, chain, id, extra, nil)
}

func (node *Node) sendKeeperResponseWithReferences(ctx context.Context, holder string, typ, chain uint8, id string, extra []byte, references []crypto.Hash) error {
	crv := byte(common.CurveSecp256k1ECDSABitcoin)
	switch chain {
	case common.SafeChainBitcoin:
	case common.SafeChainLitecoin:
		crv = common.CurveSecp256k1ECDSALitecoin
	case common.SafeChainEthereum:
		crv = common.CurveSecp256k1ECDSAEthereum
	case common.SafeChainPolygon:
		crv = common.CurveSecp256k1ECDSAPolygon
	default:
		panic(chain)
	}
	op := &common.Operation{
		Id:     id,
		Type:   typ,
		Curve:  crv,
		Public: holder,
		Extra:  extra,
	}
	return node.sendKeeperTransactionWithReferences(ctx, op, references)
}

func (node *Node) sendKeeperTransactionWithReferences(ctx context.Context, op *common.Operation, references []crypto.Hash) error {
	if len(references) > 2 {
		panic(len(references))
	}
	extra := common.AESEncrypt(node.aesKey[:], op.Encode(), op.Id)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.sendKeeperTransaction(%v) omitted %x", op, extra))
	}
	members := node.GetKeepers()
	threshold := node.keeper.Genesis.Threshold
	traceId := fmt.Sprintf("OBSERVER:%s:KEEPER:%v:%d", node.conf.App.AppId, members, threshold)
	traceId = node.safeTraceId(traceId, op.Id)
	memo := mtg.EncodeMixinExtraBase64(node.conf.KeeperAppId, extra)
	err := node.sendTransactionUntilSufficient(ctx, node.conf.AssetId, members, threshold, decimal.NewFromInt(1), memo, traceId, references)
	logger.Printf("node.sendKeeperTransaction(%v) => %s %x %v", op, op.Id, extra, err)
	return err
}

func (node *Node) sendTransactionUntilSufficient(ctx context.Context, assetId string, receivers []string, threshold int, amount decimal.Decimal, memo, traceId string, references []crypto.Hash) error {
	logger.Printf("node.sendTransactionUntilSufficient(%s, %v, %d, %s, %s, %s, %v)", assetId, receivers, threshold, amount, memo, traceId, references)
	_, err := common.SendTransactionUntilSufficient(ctx, node.wallet, node.mixin, receivers, threshold, amount, traceId, assetId, memo, references, node.conf.App.SpendPrivateKey)
	return err
}
