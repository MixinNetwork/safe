package observer

type Configuration struct {
	StoreDir          string `toml:"store-dir"`
	PrivateKey        string `toml:"private-key"`
	Timestamp         int64  `toml:"timestamp"`
	KeeperStoreDir    string `toml:"keeper-store-dir"`
	KeeperPublicKey   string `toml:"keeper-public-key"`
	AssetId           string `toml:"asset-id"`
	MixinMessengerAPI string `toml:"mixin-messenger-api"`
	MixinRPC          string `toml:"mixin-rpc"`
	BitcoinRPC        string `toml:"bitcoin-rpc"`
	EthereumRPC       string `toml:"ethereum-rpc"`
	EthereumKey       string `toml:"ethereum-key"`
	MVMRPC            string `toml:"mvm-rpc"`
	MVMKey            string `toml:"mvm-key"`
	App               struct {
		ClientId   string `toml:"client-id"`
		SessionId  string `toml:"session-id"`
		PrivateKey string `toml:"private-key"`
		PinToken   string `toml:"pin-token"`
		PIN        string `toml:"pin"`
	} `toml:"app"`
}
