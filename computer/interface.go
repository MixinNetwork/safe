package computer

import (
	"context"

	"github.com/MixinNetwork/safe/messenger"
	"github.com/MixinNetwork/trusted-group/mtg"
)

type Configuration struct {
	AppId                   string             `toml:"app-id"`
	StoreDir                string             `toml:"store-dir"`
	MessengerConversationId string             `toml:"messenger-conversation-id"`
	MonitorConversaionId    string             `toml:"monitor-conversation-id"`
	SharedKey               string             `toml:"shared-key"`
	PublicKey               string             `toml:"public-key"`
	Threshold               int                `toml:"threshold"`
	AssetId                 string             `toml:"asset-id"`
	ObserverAssetId         string             `toml:"observer-asset-id"`
	SaverAPI                string             `toml:"saver-api"`
	SaverKey                string             `toml:"saver-key"`
	MixinMessengerAPI       string             `toml:"mixin-messenger-api"`
	MixinRPC                string             `toml:"mixin-rpc"`
	SolanaRPC               string             `toml:"solana-rpc"`
	SolanaKey               string             `toml:"solana-key"`
	SolanaDepositEntry      string             `toml:"solana-deposit-entry"`
	MTG                     *mtg.Configuration `toml:"mtg"`
}

func (c *Configuration) Messenger() *messenger.MixinConfiguration {
	return &messenger.MixinConfiguration{
		UserId:         c.MTG.App.AppId,
		SessionId:      c.MTG.App.SessionId,
		Key:            c.MTG.App.SessionPrivateKey,
		ConversationId: c.MessengerConversationId,
		ReceiveBuffer:  128,
		SendBuffer:     64,
	}
}

type Network interface {
	ReceiveMessage(context.Context) (*messenger.MixinMessage, error)
	QueueMessage(ctx context.Context, receiver string, b []byte) error
}
