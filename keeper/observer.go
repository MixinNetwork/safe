package keeper

import (
	"context"
	"fmt"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/gofrs/uuid/v5"
)

func (node *Node) buildObserverResponseWithStorageTraceId(ctx context.Context, id string, sequence uint64, typ, crv byte, storageTraceId string) *mtg.Transaction {
	return node.buildObserverResponseWithAssetAndStorageTraceId(ctx, id, sequence, typ, crv, node.conf.ObserverAssetId, "1", storageTraceId)
}

func (node *Node) buildObserverResponseWithAssetAndStorageTraceId(ctx context.Context, id string, sequence uint64, typ, crv byte, assetId, amount, storageTraceId string) *mtg.Transaction {
	op := &common.Operation{
		Type:  typ,
		Id:    id,
		Curve: crv,
		Extra: uuid.FromStringOrNil(storageTraceId).Bytes(),
	}
	return node.buildObserverTransaction(ctx, op, sequence, assetId, amount, storageTraceId)
}

func (node *Node) encryptObserverOperation(op *common.Operation) []byte {
	extra := op.Encode()
	return common.AESEncrypt(node.observerAESKey[:], extra, op.Id)
}

func (node *Node) buildObserverTransaction(ctx context.Context, op *common.Operation, sequence uint64, assetId, amount, storageTraceId string) *mtg.Transaction {
	extra := node.encryptObserverOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.buildObserverTransaction(%v) omitted %x", op, extra))
	}
	members := []string{node.conf.ObserverUserId}
	threshold := 1
	return node.buildTransactionWithStorageTraceId(ctx, sequence, node.conf.ObserverUserId, assetId, members, threshold, amount, extra, op.Id, storageTraceId)
}
