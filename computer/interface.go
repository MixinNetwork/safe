package computer

import (
	"context"

	"github.com/MixinNetwork/safe/messenger"
	"github.com/MixinNetwork/trusted-group/mtg"
)

type Configuration struct {
	AppId                   string             `toml:"app-id"`
	KeeperAppId             string             `toml:"keeper-app-id"`
	StoreDir                string             `toml:"store-dir"`
	MessengerConversationId string             `toml:"messenger-conversation-id"`
	MonitorConversaionId    string             `toml:"monitor-conversation-id"`
	ObserverUserId          string             `toml:"observer-user-id"`
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
