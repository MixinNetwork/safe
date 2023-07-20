package observer

type Configuration struct {
	StoreDir           string `toml:"store-dir"`
	PrivateKey         string `toml:"private-key"`
	Timestamp          int64  `toml:"timestamp"`
	KeeperStoreDir     string `toml:"keeper-store-dir"`
	KeeperPublicKey    string `toml:"keeper-public-key"`
	AssetId            string `toml:"asset-id"`
	PriceAssetId       string `toml:"price-asset-id"`
	PriceAmount        string `toml:"price-amount"`
	TransactionMinimum string `toml:"transaction-minimum"`
	MixinMessengerAPI  string `toml:"mixin-messenger-api"`
	MixinRPC           string `toml:"mixin-rpc"`
	BitcoinRPC         string `toml:"bitcoin-rpc"`
	LitecoinRPC        string `toml:"litecoin-rpc"`
	MVMRPC             string `toml:"mvm-rpc"`
	MVMKey             string `toml:"mvm-key"`
	App                struct {
		ClientId   string `toml:"client-id"`
		SessionId  string `toml:"session-id"`
		PrivateKey string `toml:"private-key"`
		PinToken   string `toml:"pin-token"`
		PIN        string `toml:"pin"`
	} `toml:"app"`
}
