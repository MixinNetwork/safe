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

func (node *Node) buildStorageTransaction(ctx context.Context, req *common.Request, extra []byte) *mtg.Transaction {
	logger.Printf("node.writeStorageTransaction(%x)", extra)
	if common.CheckTestEnvironment(ctx) {
		tx := req.Output.BuildStorageTransaction(ctx, extra)
		v := hex.EncodeToString(extra)
		o, err := node.store.ReadProperty(ctx, tx.TraceId)
		if err != nil {
			panic(err)
		}
		if o == v {
			return tx
		}
		err = node.store.WriteProperty(ctx, tx.TraceId, v)
		if err != nil {
			panic(err)
		}
		return tx
	}

	enough := req.Output.CheckAssetBalanceForStorageAt(ctx, extra)
	if !enough {
		return nil
	}
	stx := req.Output.BuildStorageTransaction(ctx, extra)
	logger.Printf("group.BuildStorageTransaction(%x) => %v", extra, stx)
	return stx
}

func (node *Node) buildSignerResultTransaction(ctx context.Context, op *common.Operation, act *mtg.Action) (*mtg.Transaction, string) {
	extra := encodeOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.buildKeeperTransaction(%v) omitted %x", op, extra))
	}

	amount := decimal.NewFromInt(1)
	if !common.CheckTestEnvironment(ctx) {
		balance := act.CheckAssetBalanceAt(ctx, node.conf.AssetId)
		if balance.Cmp(amount) < 0 {
			return nil, node.conf.AssetId
		}
	}

	members := node.GetMembers()
	threshold := node.conf.MTG.Genesis.Threshold
	traceId := common.UniqueId(node.group.GenesisId(), op.Id)
	tx := act.BuildTransaction(ctx, traceId, node.conf.AppId, node.conf.AssetId, amount.String(), string(extra), members, threshold)
	logger.Printf("node.buildKeeperTransaction(%v) => %s %x %x", op, traceId, extra, tx.Serialize())
	return tx, ""
}

func (node *Node) sendSignerPrepareTransaction(ctx context.Context, op *common.Operation) error {
	if op.Type != common.OperationTypeSignInput {
		panic(op.Type)
	}
	op.Extra = []byte(PrepareExtra)
	extra := encodeOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.sendSignerPrepareTransaction(%v) omitted %x", op, extra))
	}
	traceId := fmt.Sprintf("SESSION:%s:SIGNER:%s:PREPARE", op.Id, string(node.id))

	return node.sendTransactionToGroupUntilSufficient(ctx, extra, traceId)
}

func (node *Node) sendSignerResultTransaction(ctx context.Context, op *common.Operation) error {
	extra := encodeOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.sendSignerResultTransaction(%v) omitted %x", op, extra))
	}
	traceId := fmt.Sprintf("SESSION:%s:SIGNER:%s:RESULT", op.Id, string(node.id))

	return node.sendTransactionToGroupUntilSufficient(ctx, extra, traceId)
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
