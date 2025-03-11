package keeper

import (
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/safe/mtg"
)

type Configuration struct {
	AppId                       string             `toml:"app-id"`
	SignerAppId                 string             `toml:"signer-app-id"`
	StoreDir                    string             `toml:"store-dir"`
	MonitorConversaionId        string             `toml:"monitor-conversation-id"`
	SharedKey                   string             `toml:"shared-key"`
	SignerPublicKey             string             `toml:"signer-public-key"`
	AssetId                     string             `toml:"asset-id"`
	ObserverAssetId             string             `toml:"observer-asset-id"`
	ObserverPublicKey           string             `toml:"observer-public-key"`
	ObserverUserId              string             `toml:"observer-user-id"`
	MixinMessengerAPI           string             `toml:"mixin-messenger-api"`
	MixinRPC                    string             `toml:"mixin-rpc"`
	BitcoinRPC                  string             `toml:"bitcoin-rpc"`
	LitecoinRPC                 string             `toml:"litecoin-rpc"`
	EthereumRPC                 string             `toml:"ethereum-rpc"`
	PolygonRPC                  string             `toml:"polygon-rpc"`
	PolygonFactoryAddress       string             `toml:"polygon-factory-address"`
	PolygonObserverDepositEntry string             `toml:"polygon-observer-deposit-entry"`
	PolygonKeeperDepositEntry   string             `toml:"polygon-keeper-deposit-entry"`
	MTG                         *mtg.Configuration `toml:"mtg"`
}

func OpenSQLite3Store(path string) (*store.SQLite3Store, error) {
	return store.OpenSQLite3Store(path)
}

func OpenSQLite3ReadOnlyStore(path string) (*store.SQLite3Store, error) {
	return store.OpenSQLite3ReadOnlyStore(path)
}
