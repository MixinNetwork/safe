package keeper

import (
	"context"
	"encoding/hex"
	"time"

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
	abi.InitFactoryContractAddress(conf.MVMFactoryAddress)
	return node
}

func (node *Node) Boot(ctx context.Context) {
	terminated, err := node.store.ReadTerminate(ctx)
	if err != nil || terminated {
		panic(err)
	}
	err = node.migrate(ctx)
	if err != nil {
		panic(err)
	}
}

func (node *Node) Terminate(ctx context.Context) ([]*mtg.Transaction, string, error) {
	err := node.store.WriteTerminate(ctx)
	panic(err)
	return nil, "", err
}

func (node *Node) Index() int {
	for i, id := range node.conf.MTG.Genesis.Members {
		if node.conf.MTG.App.AppId == id {
			return i
		}
	}
	panic(node.conf.MTG.App.AppId)
}

func (node *Node) buildTransaction(ctx context.Context, sequence uint64, assetId string, receivers []string, threshold int, amount string, memo []byte, traceId string) (*mtg.Transaction, string, error) {
	logger.Printf("node.buildTransaction(%s, %v, %d, %s, %x, %s)", assetId, receivers, threshold, amount, memo, traceId)
	return node.buildTransactionWithReferences(ctx, sequence, assetId, receivers, threshold, amount, memo, traceId, crypto.Hash{})
}

func (node *Node) buildTransactionWithReferences(ctx context.Context, sequence uint64, assetId string, receivers []string, threshold int, amount string, memo []byte, traceId string, tx crypto.Hash) (*mtg.Transaction, string, error) {
	logger.Printf("node.buildTransactionWithReferences(%s, %v, %d, %s, %x, %s, %s)", assetId, receivers, threshold, amount, memo, traceId, tx)

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
			return nil, "", err
		}
	} else {
		balance, err := node.group.CheckAssetBalanceAt(ctx, node.group.GroupId, assetId, sequence)
		if err != nil {
			return nil, "", err
		}
		amt, err := decimal.NewFromString(amount)
		if err != nil {
			return nil, "", err
		}
		if balance.Cmp(amt) < 0 {
			return nil, assetId, nil
		}
	}

	traceId = common.UniqueId(node.group.GenesisId(), traceId)
	if tx.HasValue() {
		return node.group.BuildTransactionWithReference(traceId, node.group.GroupId, assetId, amount, string(memo), receivers, threshold, sequence, tx), "", nil
	}
	return node.group.BuildTransaction(traceId, node.group.GroupId, assetId, amount, string(memo), receivers, threshold, sequence), "", nil
}

func (node *Node) verifyKernelTransaction(ctx context.Context, out *mtg.Action) error {
	if common.CheckTestEnvironment(ctx) {
		return nil
	}
	return common.VerifyKernelTransaction(node.conf.MixinRPC, out, time.Minute)
}
