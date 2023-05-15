package observer

import (
	"context"
	"fmt"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/shopspring/decimal"
)

func (node *Node) checkSafeInternalAddress(ctx context.Context, receiver string) (bool, error) {
	safe, err := node.keeperStore.ReadSafeByAddress(ctx, receiver)
	if err != nil {
		return false, fmt.Errorf("keeperStore.ReadSafeByAddress(%s) => %v", receiver, err)
	}
	holder, err := node.keeperStore.ReadAccountantHolder(ctx, receiver)
	if err != nil {
		return false, fmt.Errorf("keeperStore.ReadAccountantHolder(%s) => %v", receiver, err)
	}
	return safe != nil || holder != "", nil
}

func (node *Node) sendBitcoinKeeperResponse(ctx context.Context, holder string, typ, chain uint8, id string, extra []byte) error {
	crv := byte(common.CurveSecp256k1ECDSABitcoin)
	switch chain {
	case keeper.SafeChainBitcoin:
	case keeper.SafeChainLitecoin:
		crv = common.CurveSecp256k1ECDSALitecoin
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
	return node.sendKeeperTransaction(ctx, op)
}

func (node *Node) sendKeeperTransaction(ctx context.Context, op *common.Operation) error {
	extra := common.AESEncrypt(node.aesKey[:], op.Encode(), op.Id)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.sendKeeperTransaction(%v) omitted %x", op, extra))
	}
	members := node.keeper.Genesis.Members
	threshold := node.keeper.Genesis.Threshold
	traceId := fmt.Sprintf("OBSERVER:%s:KEEPER:%v:%d", node.conf.App.ClientId, members, threshold)
	traceId = node.safeTraceId(traceId, op.Id)
	memo := common.Base91Encode(extra)
	pin := node.conf.App.PIN
	err := common.SendTransactionUntilSufficient(ctx, node.mixin, node.conf.AssetId, members, threshold, decimal.NewFromInt(1), memo, traceId, pin)
	logger.Printf("node.sendKeeperTransaction(%v) => %s %x %v", op, op.Id, extra, err)
	return err
}
