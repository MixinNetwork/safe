package keeper

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go"
)

type Node struct {
	conf           *Configuration
	group          *mtg.Group
	signer         *mtg.Configuration
	signerAESKey   [32]byte
	observerAESKey [32]byte
	store          *store.SQLite3Store
	terminated     bool
}

func NewNode(store *store.SQLite3Store, group *mtg.Group, conf *Configuration, signer *mtg.Configuration) *Node {
	node := &Node{
		conf:   conf,
		group:  group,
		signer: signer,
		store:  store,
	}
	node.signerAESKey = common.ECDHEd25519(conf.SharedKey, conf.SignerPublicKey)
	node.observerAESKey = common.ECDHEd25519(conf.SharedKey, conf.ObserverPublicKey)
	return node
}

func (node *Node) Boot(ctx context.Context) {
	go node.loopProcessRequests(ctx)
}

func (node *Node) Index() int {
	for i, id := range node.conf.MTG.Genesis.Members {
		if node.conf.MTG.App.ClientId == id {
			return i
		}
	}
	panic(node.conf.MTG.App.ClientId)
}

func (node *Node) buildTransaction(ctx context.Context, assetId string, receivers []string, threshold int, amount string, memo []byte, traceId string) error {
	logger.Printf("node.buildTransaction(%s, %v, %d, %s, %x, %s)", assetId, receivers, threshold, amount, memo, traceId)
	if common.CheckTestEnvironment(ctx) {
		v, _ := json.Marshal(map[string]any{
			"asset_id":  assetId,
			"amount":    amount,
			"receivers": receivers,
			"threshold": threshold,
			"memo":      hex.EncodeToString(memo),
		})
		return node.store.WriteProperty(ctx, traceId, string(v))
	}
	traceId = mixin.UniqueConversationID(node.group.GenesisId(), traceId)
	return node.group.BuildTransaction(ctx, assetId, receivers, threshold, amount, string(memo), traceId, "")
}

func (node *Node) verifyKernelTransaction(ctx context.Context, out *mtg.Output) error {
	if common.CheckTestEnvironment(ctx) {
		return nil
	}
	return common.VerifyKernelTransaction(node.conf.MixinRPC, out, time.Minute)
}
