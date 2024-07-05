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

func (node *Node) Terminate(ctx context.Context) ([]*mtg.Transaction, string, error) {
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

func (node *Node) buildTransaction(ctx context.Context, sequence uint64, opponentAppId, assetId string, receivers []string, threshold int, amount string, memo []byte, traceId string) (*mtg.Transaction, string, error) {
	logger.Printf("node.buildTransaction(%s, %s, %v, %d, %s, %x, %s)", opponentAppId, assetId, receivers, threshold, amount, memo, traceId)
	return node.buildTransactionWithReferences(ctx, sequence, opponentAppId, assetId, receivers, threshold, amount, memo, traceId, crypto.Hash{})
}

func (node *Node) buildTransactionWithReferences(ctx context.Context, sequence uint64, opponentAppId, assetId string, receivers []string, threshold int, amount string, memo []byte, traceId string, tx crypto.Hash) (*mtg.Transaction, string, error) {
	logger.Printf("node.buildTransactionWithReferences(%s, %v, %d, %s, %x, %s, %s)", assetId, receivers, threshold, amount, memo, traceId, tx)
	traceId, compact, err := node.checkTransaction(ctx, sequence, assetId, receivers, threshold, amount, memo, traceId)
	if err != nil || compact != "" {
		return nil, compact, err
	}

	if tx.HasValue() {
		return node.group.BuildTransactionWithReference(traceId, opponentAppId, assetId, amount, string(memo), receivers, threshold, tx), "", nil
	}
	return node.group.BuildTransaction(traceId, opponentAppId, assetId, amount, string(memo), receivers, threshold), "", nil
}

func (node *Node) buildTransactionWithStorageTraceId(ctx context.Context, sequence uint64, opponentAppId, assetId string, receivers []string, threshold int, amount string, memo []byte, traceId, storageTraceId string) (*mtg.Transaction, string, error) {
	logger.Printf("node.buildTransactionWithStorageTraceId(%s, %v, %d, %s, %x, %s, %s)", assetId, receivers, threshold, amount, memo, traceId, storageTraceId)
	traceId, compact, err := node.checkTransaction(ctx, sequence, assetId, receivers, threshold, amount, memo, traceId)
	if err != nil || compact != "" {
		return nil, compact, err
	}

	return node.group.BuildTransactionWithStorageTraceId(traceId, opponentAppId, assetId, amount, string(memo), receivers, threshold, storageTraceId), "", nil
}

func (node *Node) checkTransaction(ctx context.Context, sequence uint64, assetId string, receivers []string, threshold int, amount string, memo []byte, traceId string) (string, string, error) {
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
			return "", "", err
		}
	} else {
		balance := node.group.CheckAssetBalanceAt(ctx, node.conf.AppId, assetId, sequence)
		amt, err := decimal.NewFromString(amount)
		if err != nil {
			panic(amount)
		}
		if balance.Cmp(amt) < 0 {
			return "", assetId, nil
		}
	}

	traceId = common.UniqueId(node.group.GenesisId(), traceId)
	return traceId, "", nil
}

func (node *Node) verifyKernelTransaction(ctx context.Context, out *mtg.Action) error {
	if common.CheckTestEnvironment(ctx) {
		return nil
	}
	return common.VerifyKernelTransaction(node.conf.MixinRPC, out, time.Minute)
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

func (node *Node) getMigrateAsset(ctx context.Context, safe *store.Safe, assetId string) (*store.MigrateAsset, error) {
	_, safeAssetId, _, err := node.getBondAsset(ctx, node.conf.PolygonObserverDepositEntry, assetId, safe.Holder)
	if err != nil {
		return nil, err
	}
	return &store.MigrateAsset{
		Chain:       safe.Chain,
		Address:     safe.Address,
		AssetId:     assetId,
		SafeAssetId: safeAssetId,
	}, nil
}

func (node *Node) Migrate(ctx context.Context) error {
	safes, err := node.store.ListUnmigratedSafesWithState(ctx, common.RequestStateDone)
	if err != nil {
		return err
	}

	var ms []*store.MigrateAsset
	for _, safe := range safes {
		chainAssetId := common.SafeChainAssetId(safe.Chain)
		ma, err := node.getMigrateAsset(ctx, safe, chainAssetId)
		if err != nil {
			return err
		}
		ms = append(ms, ma)

		switch safe.Chain {
		case common.SafeChainEthereum, common.SafeChainMVM, common.SafeChainPolygon:
			bs, err := node.store.ReadUnmigratedEthereumAllBalance(ctx, safe.Address)
			if err != nil {
				return err
			}
			for _, balance := range bs {
				if balance.AssetId == chainAssetId {
					continue
				}
				ma, err := node.getMigrateAsset(ctx, safe, balance.AssetId)
				if err != nil {
					return err
				}
				ms = append(ms, ma)
			}
		}
	}

	return node.store.Migrate(ctx, ms)
}
