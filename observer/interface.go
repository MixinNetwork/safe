package observer

import (
	"fmt"

	"github.com/shopspring/decimal"
)

type Configuration struct {
	KeeperAppId                 string      `toml:"keeper-app-id"`
	StoreDir                    string      `toml:"store-dir"`
	PrivateKey                  string      `toml:"private-key"`
	Timestamp                   int64       `toml:"timestamp"`
	KeeperStoreDir              string      `toml:"keeper-store-dir"`
	MonitorConversaionId        string      `toml:"monitor-conversation-id"`
	KeeperPublicKey             string      `toml:"keeper-public-key"`
	AssetId                     string      `toml:"asset-id"`
	CustomKeyPriceAssetId       string      `toml:"custom-key-price-asset-id"`
	CustomKeyPriceAmount        string      `toml:"custom-key-price-amount"`
	MixinMessengerAPI           string      `toml:"mixin-messenger-api"`
	MixinRPC                    string      `toml:"mixin-rpc"`
	BitcoinRPC                  string      `toml:"bitcoin-rpc"`
	LitecoinRPC                 string      `toml:"litecoin-rpc"`
	EthereumRPC                 string      `toml:"ethereum-rpc"`
	PolygonRPC                  string      `toml:"polygon-rpc"`
	PolygonFactoryAddress       string      `toml:"polygon-factory-address"`
	PolygonObserverDepositEntry string      `toml:"polygon-observer-deposit-entry"`
	PolygonKeeperDepositEntry   string      `toml:"polygon-keeper-deposit-entry"`
	EVMKey                      string      `toml:"evm-key"`
	SignerKeyThreshold          int64       `toml:"signer-key-threshold"`
	Bitcoin                     ChainParams `toml:"bitcoin"`
	Litecoin                    ChainParams `toml:"litecoin"`
	Ethereum                    ChainParams `toml:"ethereum"`
	Polygon                     ChainParams `toml:"polygon"`
	App                         struct {
		AppId               string `toml:"app-id"`
		SessionId           string `toml:"session-id"`
		SessionPrivateKey   string `toml:"session-private-key"`
		ServerPublicKey     string `toml:"server-public-key"`
		SpendPrivateKey     string `toml:"spend-private-key"`
		IsSpendKeyCanonical bool   `toml:"is-spend-key-canonical"`
	} `toml:"app"`
}

type ChainParams struct {
	OperationPriceAssetId string `toml:"operation-price-asset-id"`
	OperationPriceAmount  string `toml:"operation-price-amount"`
	TransactionMinimum    string `toml:"transaction-minimum"`
}

func (c *Configuration) Validate() error {
	if decimal.RequireFromString(c.CustomKeyPriceAmount).Sign() <= 0 {
		return fmt.Errorf("Configuration.Validate(observer) price %s", c.CustomKeyPriceAmount)
	}
	for _, p := range []ChainParams{c.Bitcoin, c.Litecoin, c.Ethereum, c.Polygon} {
		if decimal.RequireFromString(p.OperationPriceAmount).Sign() <= 0 {
			return fmt.Errorf("Configuration.Validate(operation) price %s", p.OperationPriceAmount)
		}
		if decimal.RequireFromString(p.TransactionMinimum).Sign() <= 0 {
			return fmt.Errorf("Configuration.Validate(transaction) minimum %s", p.TransactionMinimum)
		}
	}
	return nil
}
