package observer

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/shopspring/decimal"
)

func (node *Node) deriveBIP32WithKeeperPath(ctx context.Context, public, path string) (string, error) {
	path8 := common.DecodeHexOrPanic(path)
	if path8[0] > 3 {
		panic(path8[0])
	}
	path32 := make([]uint32, path8[0])
	for i := 0; i < int(path8[0]); i++ {
		path32[i] = uint32(path8[1+i])
	}
	sk, err := node.keeperStore.ReadKey(ctx, public)
	if err != nil {
		return "", fmt.Errorf("keeperStore.ReadKey(%s) => %v", public, err)
	}
	_, sdk, err := bitcoin.DeriveBIP32(public, common.DecodeHexOrPanic(sk.Extra), path32...)
	return sdk, err
}

func (node *Node) checkTrustedSender(ctx context.Context, address string) (bool, error) {
	if slices.Contains([]string{
		"bc1ql24x05zhqrpejar0p3kevhu48yhnnr3r95sv4y",
		"ltc1qs46hqx885kpz83vfg6evm9dsuapznfaw997qwl",
		"0x1616b057F8a89955d4A4f9fd9Eb10289ac0e44A1",
	}, address) {
		return true, nil
	}
	safe, err := node.keeperStore.ReadSafeByAddress(ctx, address)
	if err != nil {
		return false, fmt.Errorf("keeperStore.ReadSafeByAddress(%s) => %v", address, err)
	}
	return safe != nil, nil
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
	case common.SafeChainMVM:
		crv = common.CurveSecp256k1ECDSAMVM
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
	members := node.keeper.Genesis.Members
	threshold := node.keeper.Genesis.Threshold
	traceId := fmt.Sprintf("OBSERVER:%s:KEEPER:%v:%d", node.conf.App.AppId, members, threshold)
	traceId = node.safeTraceId(traceId, op.Id)
	memo := mtg.EncodeMixinExtra(node.conf.KeeperAppId, string(extra))
	err := node.sendTransactionUntilSufficient(ctx, node.conf.AssetId, members, threshold, decimal.NewFromInt(1), memo, traceId, references)
	logger.Printf("node.sendKeeperTransaction(%v) => %s %x %v", op, op.Id, extra, err)
	return err
}

func (node *Node) sendTransactionUntilSufficient(ctx context.Context, assetId string, receivers []string, threshold int, amount decimal.Decimal, memo, traceId string, references []crypto.Hash) error {
	for {
		err := node.sendTransaction(ctx, assetId, receivers, threshold, amount, memo, traceId, references)
		if err != nil && strings.Contains(err.Error(), "Insufficient") {
			time.Sleep(7 * time.Second)
			continue
		}
		if err != nil && mtg.CheckRetryableError(err) {
			time.Sleep(7 * time.Second)
			continue
		}
		return err
	}
}

func (node *Node) sendTransaction(ctx context.Context, assetId string, receivers []string, threshold int, amount decimal.Decimal, memo, traceId string, references []crypto.Hash) error {
	logger.Printf("node.sendTransaction(%s, %v, %d, %s, %s, %s, %v)", assetId, receivers, threshold, amount, memo, traceId, references)
	_, err := common.SendTransactionUntilSufficient(ctx, node.mixin, []string{node.conf.App.AppId}, 1, receivers, threshold, amount, traceId, assetId, memo, node.conf.App.SpendPrivateKey)
	return err
}
