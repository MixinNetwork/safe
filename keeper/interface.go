package keeper

import (
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
)

type Configuration struct {
	AppId                 string             `toml:"app-id"`
	SignerAppId           string             `toml:"signer-app-id"`
	StoreDir              string             `toml:"store-dir"`
	MonitorConversaionId  string             `toml:"monitor-conversation-id"`
	SharedKey             string             `toml:"shared-key"`
	SignerPublicKey       string             `toml:"signer-public-key"`
	AssetId               string             `toml:"asset-id"`
	ObserverAssetId       string             `toml:"observer-asset-id"`
	ObserverPublicKey     string             `toml:"observer-public-key"`
	ObserverUserId        string             `toml:"observer-user-id"`
	MixinMessengerAPI     string             `toml:"mixin-messenger-api"`
	MixinRPC              string             `toml:"mixin-rpc"`
	BitcoinRPC            string             `toml:"bitcoin-rpc"`
	LitecoinRPC           string             `toml:"litecoin-rpc"`
	EthereumRPC           string             `toml:"ethereum-rpc"`
	MVMRPC                string             `toml:"mvm-rpc"`
	PolygonRPC            string             `toml:"polygon-rpc"`
	MVMFactoryAddress     string             `toml:"mvm-factory-address"`
	PolygonFactoryAddress string             `toml:"polygon-factory-address"`
	PolygonObserverEntry  string             `toml:"polygon-observer-entry"`
	PolygonGroupEntry     string             `toml:"polygon-group-entry"`
	MTG                   *mtg.Configuration `toml:"mtg"`
}

func OpenSQLite3Store(path string) (*store.SQLite3Store, error) {
	return store.OpenSQLite3Store(path)
}

func OpenSQLite3ReadOnlyStore(path string) (*store.SQLite3Store, error) {
	return store.OpenSQLite3ReadOnlyStore(path)
}
