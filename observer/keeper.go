package observer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/bot-api-go-client"
	"github.com/MixinNetwork/go-number"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
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

func (node *Node) checkSafeInternalAddress(ctx context.Context, receiver string) (bool, error) {
	safe, err := node.keeperStore.ReadSafeByAddress(ctx, receiver)
	if err != nil {
		return false, fmt.Errorf("keeperStore.ReadSafeByAddress(%s) => %v", receiver, err)
	}
	return safe != nil, nil
}

func (node *Node) sendBitcoinKeeperResponse(ctx context.Context, holder string, typ, chain uint8, id string, extra []byte) error {
	return node.sendBitcoinKeeperResponseWithReferences(ctx, holder, typ, chain, id, extra, nil)
}

func (node *Node) sendBitcoinKeeperResponseWithReferences(ctx context.Context, holder string, typ, chain uint8, id string, extra []byte, references []crypto.Hash) error {
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
	traceId := fmt.Sprintf("OBSERVER:%s:KEEPER:%v:%d", node.conf.App.ClientId, members, threshold)
	traceId = node.safeTraceId(traceId, op.Id)
	memo := common.Base91Encode(extra)
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
		if err != nil && strings.Contains(err.Error(), "Client.Timeout exceeded") {
			time.Sleep(7 * time.Second)
			continue
		}
		return err
	}
}

func (node *Node) sendTransaction(ctx context.Context, assetId string, receivers []string, threshold int, amount decimal.Decimal, memo, traceId string, references []crypto.Hash) error {
	logger.Printf("node.sendTransaction(%s, %v, %d, %s, %s, %s, %v)", assetId, receivers, threshold, amount, memo, traceId, references)
	conf := node.conf.App
	input := &bot.TransferInput{
		AssetId: assetId,
		Amount:  number.FromString(amount.String()),
		TraceId: traceId,
		Memo:    memo,
	}
	for i := range references {
		input.References = append(input.References, references[i].String())
	}
	if len(receivers) == 1 {
		input.RecipientId = receivers[0]
		_, err := bot.CreateTransfer(ctx, input, conf.ClientId, conf.SessionId, conf.PrivateKey, conf.PIN, conf.PinToken)
		return err
	}
	input.OpponentMultisig.Receivers = receivers
	input.OpponentMultisig.Threshold = int64(threshold)
	_, err := bot.CreateMultisigTransaction(ctx, input, conf.ClientId, conf.SessionId, conf.PrivateKey, conf.PIN, conf.PinToken)
	return err
}
