package computer

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/shopspring/decimal"
)

func (node *Node) checkTransaction(ctx context.Context, act *mtg.Action, assetId string, receivers []string, threshold int, destination, tag, amount string, memo []byte, traceId string) string {
	if common.CheckTestEnvironment(ctx) {
		v := common.MarshalJSONOrPanic(map[string]any{
			"asset_id":    assetId,
			"amount":      amount,
			"receivers":   receivers,
			"threshold":   threshold,
			"destination": destination,
			"tag":         tag,
			"memo":        hex.EncodeToString(memo),
		})
		err := node.store.WriteProperty(ctx, traceId, string(v))
		if err != nil {
			panic(err)
		}
	} else {
		balance := act.CheckAssetBalanceAt(ctx, assetId)
		logger.Printf("group.CheckAssetBalanceAt(%s, %d) => %s %s %s", assetId, act.Sequence, traceId, amount, balance)
		amt, err := decimal.NewFromString(amount)
		if err != nil {
			panic(amount)
		}
		if balance.Cmp(amt) < 0 {
			return ""
		}
	}

	nextId := common.UniqueId(node.group.GenesisId(), traceId)
	logger.Printf("node.checkTransaction(%s) => %s", traceId, nextId)
	return nextId
}

func (node *Node) buildWithdrawalTransaction(ctx context.Context, act *mtg.Action, assetId, amount string, memo []byte, destination, tag, traceId string) *mtg.Transaction {
	logger.Printf("node.buildTransactionWithReferences(%s, %s, %x, %s, %s, %s)", assetId, amount, memo, destination, tag, traceId)
	traceId = node.checkTransaction(ctx, act, assetId, nil, 0, destination, tag, amount, memo, traceId)
	if traceId == "" {
		return nil
	}

	return act.BuildWithdrawTransaction(ctx, traceId, assetId, amount, string(memo), destination, tag)
}

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
