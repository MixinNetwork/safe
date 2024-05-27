package keeper

import (
	"context"
	"fmt"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
)

func (node *Node) sendObserverResponseWithReferences(ctx context.Context, id string, sequence uint64, typ, crv byte, tx crypto.Hash) (*mtg.Transaction, string, error) {
	return node.sendObserverResponseWithAssetAndReferences(ctx, id, sequence, typ, crv, node.conf.ObserverAssetId, "1", tx)
}

func (node *Node) sendObserverResponseWithAssetAndReferences(ctx context.Context, id string, sequence uint64, typ, crv byte, assetId, amount string, tx crypto.Hash) (*mtg.Transaction, string, error) {
	op := &common.Operation{
		Type:  typ,
		Id:    id,
		Curve: crv,
		Extra: tx[:],
	}
	return node.buildObserverTransaction(ctx, op, sequence, assetId, amount, tx)
}

func (node *Node) encryptObserverOperation(op *common.Operation) []byte {
	extra := op.Encode()
	return common.AESEncrypt(node.observerAESKey[:], extra, op.Id)
}

func (node *Node) buildObserverTransaction(ctx context.Context, op *common.Operation, sequence uint64, assetId, amount string, tx crypto.Hash) (*mtg.Transaction, string, error) {
	extra := node.encryptObserverOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.buildObserverTransaction(%v) omitted %x", op, extra))
	}
	members := []string{node.conf.ObserverUserId}
	threshold := 1
	t, asset, err := node.buildTransactionWithReferences(ctx, sequence, node.conf.ObserverUserId, assetId, members, threshold, amount, extra, op.Id, tx)
	logger.Printf("node.buildObserverTransaction(%v %s %x %d) => %v %s %v", op, op.Id, extra, sequence, t, asset, err)
	return t, asset, err
}
