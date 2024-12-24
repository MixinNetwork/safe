package computer

import (
	"context"
	"fmt"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/shopspring/decimal"
)

func (node *Node) sendObserverTransaction(ctx context.Context, op *common.Operation) error {
	extra := encodeOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.sendSignerResultTransaction(%v) omitted %x", op, extra))
	}

	traceId := fmt.Sprintf("SESSION:%s:SIGNER:%s:RESULT", op.Id, string(node.id))
	return node.sendTransactionToGroupUntilSufficient(ctx, extra, traceId)
}

func (node *Node) sendTransactionToGroupUntilSufficient(ctx context.Context, memo []byte, traceId string) error {
	receivers := node.GetMembers()
	threshold := node.conf.MTG.Genesis.Threshold
	amount := decimal.NewFromInt(1)
	traceId = common.UniqueId(traceId, fmt.Sprintf("MTG:%v:%d", receivers, threshold))

	if common.CheckTestEnvironment(ctx) {
		return node.mtgQueueTestOutput(ctx, memo)
	}
	m := mtg.EncodeMixinExtraBase64(node.conf.AppId, memo)
	_, err := common.SendTransactionUntilSufficient(ctx, node.mixin, []string{node.mixin.ClientID}, 1, receivers, threshold, amount, traceId, node.conf.AssetId, m, node.conf.MTG.App.SpendPrivateKey)
	return err
}

func encodeOperation(op *common.Operation) []byte {
	extra := []byte{op.Type}
	extra = append(extra, op.Extra...)
	return extra
}

func decodeOperation(extra []byte) *common.Operation {
	return &common.Operation{
		Type:  extra[0],
		Extra: extra[1:],
	}
}
