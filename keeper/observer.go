package keeper

import (
	"context"
	"fmt"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
)

func (node *Node) sendObserverResponseWithReferences(ctx context.Context, id string, typ, crv byte, tx crypto.Hash) error {
	return node.sendObserverResponseWithAssetAndReferences(ctx, id, typ, crv, node.conf.ObserverAssetId, "1", tx)
}

func (node *Node) sendObserverResponseWithAssetAndReferences(ctx context.Context, id string, typ, crv byte, assetId, amount string, tx crypto.Hash) error {
	op := &common.Operation{
		Type:  typ,
		Id:    id,
		Curve: crv,
		Extra: tx[:],
	}
	return node.buildObserverTransaction(ctx, op, assetId, amount, tx)
}

func (node *Node) encryptObserverOperation(op *common.Operation) []byte {
	extra := op.Encode()
	return common.AESEncrypt(node.observerAESKey[:], extra, op.Id)
}

func (node *Node) buildObserverTransaction(ctx context.Context, op *common.Operation, assetId, amount string, tx crypto.Hash) error {
	extra := node.encryptObserverOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.buildObserverTransaction(%v) omitted %x", op, extra))
	}
	members := []string{node.conf.ObserverUserId}
	threshold := 1
	err := node.buildTransactionWithReferences(ctx, assetId, members, threshold, amount, extra, op.Id, tx)
	logger.Printf("node.buildObserverTransaction(%v) => %s %x %v", op, op.Id, extra, err)
	return err
}
