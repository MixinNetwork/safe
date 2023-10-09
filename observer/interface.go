package observer

import (
	"fmt"

	"github.com/shopspring/decimal"
)

type Configuration struct {
	StoreDir              string `toml:"store-dir"`
	PrivateKey            string `toml:"private-key"`
	Timestamp             int64  `toml:"timestamp"`
	KeeperStoreDir        string `toml:"keeper-store-dir"`
	KeeperPublicKey       string `toml:"keeper-public-key"`
	AssetId               string `toml:"asset-id"`
	CustomKeyPriceAssetId string `toml:"custom-key-price-asset-id"`
	CustomKeyPriceAmount  string `toml:"custom-key-price-amount"`
	OperationPriceAssetId string `toml:"operation-price-asset-id"`
	OperationPriceAmount  string `toml:"operation-price-amount"`
	TransactionMinimum    string `toml:"transaction-minimum"`
	MixinMessengerAPI     string `toml:"mixin-messenger-api"`
	MixinRPC              string `toml:"mixin-rpc"`
	BitcoinRPC            string `toml:"bitcoin-rpc"`
	LitecoinRPC           string `toml:"litecoin-rpc"`
	EthereumRPC           string `toml:"ethereum-rpc"`
	MVMRPC                string `toml:"mvm-rpc"`
	MVMFactoryAddress     string `toml:"mvm-factory-address"`
	MVMKey                string `toml:"mvm-key"`
	App                   struct {
		ClientId   string `toml:"client-id"`
		SessionId  string `toml:"session-id"`
		PrivateKey string `toml:"private-key"`
		PinToken   string `toml:"pin-token"`
		PIN        string `toml:"pin"`
	} `toml:"app"`
}

func (c *Configuration) Validate() error {
	if decimal.RequireFromString(c.CustomKeyPriceAmount).Sign() <= 0 {
		return fmt.Errorf("Configuration.Validate(observer) price %s", c.CustomKeyPriceAmount)
	}
	if decimal.RequireFromString(c.OperationPriceAmount).Sign() <= 0 {
		return fmt.Errorf("Configuration.Validate(transaction) price %s", c.OperationPriceAmount)
	}
	if decimal.RequireFromString(c.TransactionMinimum).Sign() <= 0 {
		return fmt.Errorf("Configuration.Validate(transaction) minimum %s", c.TransactionMinimum)
	}
	return nil
}
