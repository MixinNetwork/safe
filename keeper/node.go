package keeper

import (
	"context"
	"encoding/hex"
	"slices"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/shopspring/decimal"
)

type Node struct {
	conf           *Configuration
	group          *mtg.Group
	signer         *mtg.Configuration
	signerAESKey   [32]byte
	observerAESKey [32]byte
	store          *store.SQLite3Store
	terminated     bool
	mixin          *mixin.Client
}

func NewNode(store *store.SQLite3Store, group *mtg.Group, conf *Configuration, signer *mtg.Configuration, mixin *mixin.Client) *Node {
	node := &Node{
		conf:   conf,
		group:  group,
		signer: signer,
		store:  store,
	}
	node.signerAESKey = common.ECDHEd25519(conf.SharedKey, conf.SignerPublicKey)
	node.observerAESKey = common.ECDHEd25519(conf.SharedKey, conf.ObserverPublicKey)
	node.mixin = mixin
	abi.InitFactoryContractAddress(conf.PolygonFactoryAddress)
	return node
}

func (node *Node) Boot(ctx context.Context) {
	terminated, err := node.store.ReadTerminate(ctx)
	if err != nil || terminated {
		panic(err)
	}
	err = node.Migrate(ctx)
	if err != nil {
		panic(err)
	}
}

func (node *Node) Terminate(ctx context.Context) ([]*mtg.Transaction, string) {
	err := node.store.WriteTerminate(ctx)
	panic(err)
}

func (node *Node) Index() int {
	index := slices.Index(node.conf.MTG.Genesis.Members, node.conf.MTG.App.AppId)
	if index >= 0 {
		return index
	}
	panic(node.conf.MTG.App.AppId)
}

func (node *Node) buildTransaction(ctx context.Context, act *mtg.Action, opponentAppId, assetId string, receivers []string, threshold int, amount string, memo []byte, traceId string) *mtg.Transaction {
	logger.Printf("node.buildTransaction(%s, %s, %v, %d, %s, %x, %s)", opponentAppId, assetId, receivers, threshold, amount, memo, traceId)
	return node.buildTransactionWithReferences(ctx, act, opponentAppId, assetId, receivers, threshold, amount, memo, traceId, crypto.Hash{})
}

func (node *Node) buildTransactionWithReferences(ctx context.Context, act *mtg.Action, opponentAppId, assetId string, receivers []string, threshold int, amount string, memo []byte, traceId string, tx crypto.Hash) *mtg.Transaction {
	logger.Printf("node.buildTransactionWithReferences(%s, %v, %d, %s, %x, %s, %s)", assetId, receivers, threshold, amount, memo, traceId, tx)
	traceId = node.checkTransaction(ctx, act, assetId, receivers, threshold, amount, memo, traceId)
	if traceId == "" {
		return nil
	}

	if tx.HasValue() {
		return act.BuildTransactionWithReference(ctx, traceId, opponentAppId, assetId, amount, string(memo), receivers, threshold, tx)
	}
	return act.BuildTransaction(ctx, traceId, opponentAppId, assetId, amount, string(memo), receivers, threshold)
}

func (node *Node) buildTransactionWithStorageTraceId(ctx context.Context, act *mtg.Action, opponentAppId, assetId string, receivers []string, threshold int, amount string, memo []byte, traceId, storageTraceId string) *mtg.Transaction {
	logger.Printf("node.buildTransactionWithStorageTraceId(%s, %v, %d, %s, %x, %s, %s)", assetId, receivers, threshold, amount, memo, traceId, storageTraceId)
	traceId = node.checkTransaction(ctx, act, assetId, receivers, threshold, amount, memo, traceId)
	if traceId == "" {
		return nil
	}

	return act.BuildTransactionWithStorageTraceId(ctx, traceId, opponentAppId, assetId, amount, string(memo), receivers, threshold, storageTraceId)
}

func (node *Node) checkTransaction(ctx context.Context, act *mtg.Action, assetId string, receivers []string, threshold int, amount string, memo []byte, traceId string) string {
	if common.CheckTestEnvironment(ctx) {
		v := common.MarshalJSONOrPanic(map[string]any{
			"asset_id":  assetId,
			"amount":    amount,
			"receivers": receivers,
			"threshold": threshold,
			"memo":      hex.EncodeToString(memo),
		})
		err := node.store.WriteProperty(ctx, traceId, string(v))
		if err != nil {
			panic(err)
		}
	} else {
		balance := act.CheckAssetBalanceAt(ctx, node.conf.AppId, assetId, act.Sequence)
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

func (node *Node) verifyKernelTransaction(ctx context.Context, out *mtg.Action) bool {
	if common.CheckTestEnvironment(ctx) {
		return false
	}
	ver, err := common.VerifyKernelTransaction(node.conf.MixinRPC, out, time.Minute)
	if err != nil {
		panic(err)
	}
	return ver.DepositData() != nil
}

func (node *Node) safeUser() bot.SafeUser {
	return bot.SafeUser{
		UserId:            node.conf.MTG.App.AppId,
		SessionId:         node.conf.MTG.App.SessionId,
		ServerPublicKey:   node.conf.MTG.App.ServerPublicKey,
		SessionPrivateKey: node.conf.MTG.App.SessionPrivateKey,
		SpendPrivateKey:   node.conf.MTG.App.SpendPrivateKey,
	}
}
