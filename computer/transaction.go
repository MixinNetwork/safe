package computer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	mc "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/shopspring/decimal"
)

func (node *Node) readStorageExtraFromObserver(ctx context.Context, ref crypto.Hash) []byte {
	if common.CheckTestEnvironment(ctx) {
		val, err := node.store.ReadProperty(ctx, ref.String())
		if err != nil {
			panic(ref.String())
		}
		raw, err := base64.RawURLEncoding.DecodeString(val)
		if err != nil {
			panic(ref.String())
		}
		return raw
	}

	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, ref.String())
	if err != nil {
		panic(ref.String())
	}

	return ver.Extra
}

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

func (node *Node) buildTransaction(ctx context.Context, act *mtg.Action, opponentAppId, assetId string, receivers []string, threshold int, amount string, memo []byte, traceId string) *mtg.Transaction {
	logger.Printf("node.buildTransaction(%s, %s, %v, %d, %s, %x, %s)", opponentAppId, assetId, receivers, threshold, amount, memo, traceId)
	return node.buildTransactionWithReferences(ctx, act, opponentAppId, assetId, receivers, threshold, amount, memo, traceId, crypto.Hash{})
}

func (node *Node) buildTransactionWithReferences(ctx context.Context, act *mtg.Action, opponentAppId, assetId string, receivers []string, threshold int, amount string, memo []byte, traceId string, tx crypto.Hash) *mtg.Transaction {
	logger.Printf("node.buildTransactionWithReferences(%s, %v, %d, %s, %x, %s, %s)", assetId, receivers, threshold, amount, memo, traceId, tx)
	traceId = node.checkTransaction(ctx, act, assetId, receivers, threshold, "", "", amount, memo, traceId)
	if traceId == "" {
		return nil
	}

	if tx.HasValue() {
		return act.BuildTransactionWithReference(ctx, traceId, opponentAppId, assetId, amount, string(memo), receivers, threshold, tx)
	}
	return act.BuildTransaction(ctx, traceId, opponentAppId, assetId, amount, string(memo), receivers, threshold)
}

func (node *Node) sendObserverTransactionToGroup(ctx context.Context, op *common.Operation, references []crypto.Hash) error {
	logger.Printf("node.sendObserverTransactionToGroup(%v)", op)
	extra := encodeOperation(op)
	extra = node.signObserverExtra(extra)

	traceId := fmt.Sprintf("SESSION:%s:OBSERVER:%s", op.Id, string(node.id))
	return node.sendTransactionToGroupUntilSufficient(ctx, extra, "0.00000001", bot.XINAssetId, traceId, references)
}

func (node *Node) sendSignerTransactionToGroup(ctx context.Context, traceId string, op *common.Operation, references []crypto.Hash) error {
	logger.Printf("node.sendSignerTransactionToGroup(%s %v)", node.id, op)
	extra := encodeOperation(op)

	return node.sendTransactionToGroupUntilSufficient(ctx, extra, "1", node.conf.AssetId, traceId, references)
}

func (node *Node) sendTransactionToGroupUntilSufficient(ctx context.Context, memo []byte, amount, assetId, traceId string, references []crypto.Hash) error {
	receivers := node.GetMembers()
	threshold := node.conf.MTG.Genesis.Threshold
	amt, err := decimal.NewFromString(amount)
	if err != nil {
		panic(err)
	}
	traceId = common.UniqueId(traceId, fmt.Sprintf("MTG:%v:%d", receivers, threshold))

	if common.CheckTestEnvironment(ctx) {
		return node.mtgQueueTestOutput(ctx, memo)
	}
	m := mtg.EncodeMixinExtraBase64(node.conf.AppId, memo)
	if len(memo)+16 <= mc.ExtraSizeGeneralLimit {
		_, err := common.SendTransactionUntilSufficient(ctx, node.mixin, []string{node.mixin.ClientID}, 1, receivers, threshold, amt, traceId, assetId, m, common.ToMixinnetHash(references), node.conf.MTG.App.SpendPrivateKey)
		return err
	}

	_, err = common.WriteStorageUntilSufficient(ctx, node.mixin, []*bot.TransactionRecipient{
		{
			MixAddress: bot.NewUUIDMixAddress(node.conf.MTG.Genesis.Members, byte(node.conf.MTG.Genesis.Threshold)),
			Amount:     amount,
		},
	}, []byte(m), traceId, *node.SafeUser())
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
