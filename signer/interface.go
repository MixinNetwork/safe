package signer

import (
	"context"

	"github.com/MixinNetwork/safe/messenger"
	"github.com/MixinNetwork/trusted-group/mtg"
)

type Configuration struct {
	StoreDir                string             `toml:"store-dir"`
	MessengerConversationId string             `toml:"messenger-conversation-id"`
	Threshold               int                `toml:"threshold"`
	SharedKey               string             `toml:"shared-key"`
	AssetId                 string             `toml:"asset-id"`
	KeeperAssetId           string             `toml:"keeper-asset-id"`
	KeeperPublicKey         string             `toml:"keeper-public-key"`
	SaverAPI                string             `toml:"saver-api"`
	SaverKey                string             `toml:"saver-key"`
	MixinRPC                string             `toml:"mixin-rpc"`
	MTG                     *mtg.Configuration `toml:"mtg"`
}

func (c *Configuration) Messenger() *messenger.MixinConfiguration {
	return &messenger.MixinConfiguration{
		UserId:         c.MTG.App.ClientId,
		SessionId:      c.MTG.App.SessionId,
		Key:            c.MTG.App.PrivateKey,
		ConversationId: c.MessengerConversationId,
		Buffer:         128,
	}
}

type Network interface {
	ReceiveMessage(context.Context) (string, []byte, error)
	QueueMessage(ctx context.Context, receiver string, b []byte) error
	BroadcastMessage(ctx context.Context, b []byte) error
}
