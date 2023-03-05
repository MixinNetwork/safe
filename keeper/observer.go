package keeper

import (
	"context"
	"fmt"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
)

func (node *Node) sendObserverResponse(ctx context.Context, id string, typ byte, extra []byte) error {
	return node.sendObserverResponseWithAsset(ctx, id, typ, extra, node.conf.ObserverAssetId, "1")
}

func (node *Node) sendObserverResponseWithAsset(ctx context.Context, id string, typ byte, extra []byte, assetId, amount string) error {
	op := &common.Operation{
		Type:  typ,
		Id:    id,
		Extra: extra,
	}
	return node.buildObserverTransaction(ctx, op, assetId, amount)
}

func (node *Node) encryptObserverOperation(op *common.Operation) []byte {
	extra := op.Encode()
	return common.AESEncrypt(node.observerAESKey[:], extra, op.Id)
}

func (node *Node) buildObserverTransaction(ctx context.Context, op *common.Operation, assetId, amount string) error {
	extra := node.encryptObserverOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.buildObserverTransaction(%v) omitted %x", op, extra))
	}
	members := []string{node.conf.ObserverUserId}
	threshold := 1
	err := node.buildTransaction(ctx, node.conf.ObserverAssetId, members, threshold, "1", extra, op.Id)
	logger.Printf("node.buildObserverTransaction(%v) => %s %x %v", op, op.Id, extra, err)
	return err
}
