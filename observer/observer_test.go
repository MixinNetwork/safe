package observer

import (
	"context"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/btcsuite/btcd/btcec/v2"
	ec "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofrs/uuid/v5"
	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

const (
	testMVMFactoryAddress       = "0x39490616B61302B7d0Af8993cB694a54064EBA17"
	testChainMVM                = 4
	testBitcoinKeyHolderPrivate = "52250bb9b9edc5d54466182778a6470a5ee34033c215c92dd250b9c2ce543556"
	testSafeAddress             = "bc1qm7qaucdjwzpapugfvmzp2xduzs7p0jd3zq7yxpvuf9dp5nml3pesx57a9x"
	testMVMBondAssetId          = "8e85c732-3bc6-3f50-939a-be89a67a6db6"
	testPolygonBondAssetId      = "728ed44b-a751-3b49-81e0-003815c8184c"
	testReceiverAddress         = "0x9d04735aaEB73535672200950fA77C2dFC86eB21"
)

func TestObserver(t *testing.T) {
	logger.SetLevel(logger.VERBOSE)
	ctx := context.Background()
	ctx = common.EnableTestEnvironment(ctx)
	require := require.New(t)

	root, err := os.MkdirTemp("", "safe-observer-test")
	require.Nil(err)
	node := testBuildNode(ctx, require, root)
	require.NotNil(node)

	fvb, err := bitcoin.EstimateAvgFee(common.SafeChainBitcoin, node.conf.BitcoinRPC)
	require.Nil(err)
	require.GreaterOrEqual(fvb, int64(5))
	require.Less(fvb, int64(500))

	now := time.Now().UTC()

	err = node.store.WriteAccountProposalIfNotExists(ctx, testReceiverAddress, time.Now())
	require.Nil(err)
	f, err := node.store.CheckAccountProposed(ctx, testReceiverAddress)
	require.Nil(err)
	require.True(f)
	a, err := node.store.ReadAccount(ctx, testReceiverAddress)
	require.Nil(err)
	require.Equal(testReceiverAddress, a.Address)
	require.False(a.ApprovedAt.Valid)
	require.Equal("", a.Signature.String)
	as, err := node.store.ListProposedAccountsWithSig(ctx)
	require.Nil(err)
	require.Len(as, 0)
	err = node.store.SaveAccountApprovalSignature(ctx, testReceiverAddress, "signature")
	require.Nil(err)
	as, err = node.store.ListProposedAccountsWithSig(ctx)
	require.Nil(err)
	require.Len(as, 1)
	err = node.store.MarkAccountDeployed(ctx, testReceiverAddress)
	require.Nil(err)
	a, err = node.store.ReadAccount(ctx, testReceiverAddress)
	require.Nil(err)
	require.True(a.DeployedAt.Time.After(now))
	as, err = node.store.ListProposedAccountsWithSig(ctx)
	require.Nil(err)
	require.Len(as, 0)
}

func TestObserverMigrateBondAsset(t *testing.T) {
	logger.SetLevel(logger.VERBOSE)
	ctx := context.Background()
	ctx = common.EnableTestEnvironment(ctx)
	require := require.New(t)

	root, err := os.MkdirTemp("", "safe-observer-test")
	require.Nil(err)
	node := testBuildNode(ctx, require, root)
	require.NotNil(node)

	holder := testPublicKey(testBitcoinKeyHolderPrivate)
	_, assetId := node.bitcoinParams(common.SafeChainBitcoin)
	asset, err := node.fetchAssetMeta(ctx, assetId)
	require.Nil(err)

	bond := getMVMFactoryAssetAddress(assetId, asset.Symbol, asset.Name, holder)
	bondId := ethereum.GenerateAssetId(testChainMVM, strings.ToLower(bond.Hex()))
	require.Equal(testMVMBondAssetId, bondId)

	abi.InitFactoryContractAddress(node.conf.PolygonFactoryAddress)
	err = abi.GetOrDeployFactoryAsset(ctx, node.conf.PolygonRPC, os.Getenv("MVM_DEPLOYER"), assetId, asset.Symbol, asset.Name, testReceiverAddress, holder)
	require.Nil(err)

	bond = abi.GetFactoryAssetAddress(testReceiverAddress, assetId, asset.Symbol, asset.Name, holder)
	bondId = ethereum.GenerateAssetId(common.SafeChainPolygon, strings.ToLower(bond.Hex()))
	require.Equal(testPolygonBondAssetId, bondId)
}

func TestAsset(t *testing.T) {
	require := require.New(t)

	abi.InitFactoryContractAddress("0x4D17777E0AC12C6a0d4DEF1204278cFEAe142a1E")

	entry := "0x11EC02748116A983deeD59235302C3139D6e8cdD" // keeper
	// entry := "0x9d04735aaEB73535672200950fA77C2dFC86eB21" // observer
	holder := "020b44b15ca73d0c0ab55c01e6b7ad5fda49b17cea6849fd33ff62fead193f6cb8"

	assetId := "76c802a2-7c88-447f-a93e-c29c9e5dd9c8"
	symbol := "LTC"
	name := "Litecoin"

	addr := abi.GetFactoryAssetAddress(entry, assetId, symbol, name, holder)
	assetKey := strings.ToLower(addr.String())
	err := ethereum.VerifyAssetKey(assetKey)
	require.Nil(err)
	safeAssetId := ethereum.GenerateAssetId(common.SafeChainPolygon, assetKey)
	require.Equal("b877b05f-a9f0-3fef-9975-6ba24d3fe7a9", safeAssetId)
}

func TestNode(t *testing.T) {
	ctx := context.Background()
	ctx = common.EnableTestEnvironment(ctx)
	require := require.New(t)

	root, err := os.MkdirTemp("", "safe-observer-test")
	require.Nil(err)
	node := testBuildNode(ctx, require, root)
	require.NotNil(node)

	k1 := &StatsInfo{
		Type: NodeTypeKeeper,
		MTG: MTGInfo{
			LatestRequest: "61d911746e291a77",
			BitcoinHeight: "861968",
			InitialTxs:    "0",
			SignedTxs:     "0",
			SnapshotTxs:   "0",
			XINOutputs:    "10",
			MSKTOutputs:   "10",
		},
		App: AppInfo{
			SignerBitcoinKeys:    "1016",
			SignerEthereumKeys:   "1036",
			ObserverBitcoinKeys:  "987",
			ObserverEthereumKeys: "1000",
			InitialTxs:           "1",
			PendingTxs:           "0",
			DoneTxs:              "246",
			FailedTxs:            "19",
			Version:              "v0.17.2-1976a7f",
		},
	}
	err = testUpsertStats(ctx, node, k1)
	require.Nil(err)
	nks, err := node.store.ListNodeStats(ctx, NodeTypeKeeper)
	require.Nil(err)
	require.Len(nks, 1)
	stats, err := nks[0].getStats()
	require.Nil(err)
	require.Equal(NodeTypeKeeper, nks[0].Type)
	require.Equal(k1.MTG.LatestRequest, stats.MTG.LatestRequest)
	require.Equal(k1.MTG.BitcoinHeight, stats.MTG.BitcoinHeight)
	require.Equal(k1.MTG.InitialTxs, stats.MTG.InitialTxs)
	require.Equal(k1.MTG.SignedTxs, stats.MTG.SignedTxs)
	require.Equal(k1.MTG.SnapshotTxs, stats.MTG.SnapshotTxs)
	require.Equal(k1.MTG.XINOutputs, stats.MTG.XINOutputs)
	require.Equal(k1.MTG.MSKTOutputs, stats.MTG.MSKTOutputs)
	require.Equal(k1.App.SignerBitcoinKeys, stats.App.SignerBitcoinKeys)
	require.Equal(k1.App.SignerEthereumKeys, stats.App.SignerEthereumKeys)
	require.Equal(k1.App.ObserverBitcoinKeys, stats.App.ObserverBitcoinKeys)
	require.Equal(k1.App.ObserverEthereumKeys, stats.App.ObserverEthereumKeys)
	require.Equal(k1.App.InitialTxs, stats.App.InitialTxs)
	require.Equal(k1.App.PendingTxs, stats.App.PendingTxs)
	require.Equal(k1.App.DoneTxs, stats.App.DoneTxs)
	require.Equal(k1.App.FailedTxs, stats.App.FailedTxs)
	require.Equal(k1.App.Version, stats.App.Version)

	s1 := &StatsInfo{
		Type: NodeTypeSigner,
		MTG: MTGInfo{
			InitialTxs:  "1",
			SignedTxs:   "0",
			SnapshotTxs: "142",
			MSKTOutputs: "10",
			MSSTOutputs: "250",
		},
		App: AppInfo{
			InitialSessions: "0",
			PendingSessions: "0",
			FinalSessions:   "14984",
			GeneratedKeys:   "2614",
			Version:         "v0.17.2-1976a7f",
		},
	}
	err = testUpsertStats(ctx, node, s1)
	require.Nil(err)
	nss, err := node.store.ListNodeStats(ctx, NodeTypeSigner)
	require.Nil(err)
	require.Len(nss, 1)
	stats, err = nss[0].getStats()
	require.Nil(err)
	require.Equal(NodeTypeSigner, nss[0].Type)
	require.Equal(s1.MTG.InitialTxs, stats.MTG.InitialTxs)
	require.Equal(s1.MTG.SignedTxs, stats.MTG.SignedTxs)
	require.Equal(s1.MTG.SnapshotTxs, stats.MTG.SnapshotTxs)
	require.Equal(s1.MTG.MSSTOutputs, stats.MTG.MSSTOutputs)
	require.Equal(s1.MTG.MSKTOutputs, stats.MTG.MSKTOutputs)
	require.Equal(s1.App.InitialSessions, stats.App.InitialSessions)
	require.Equal(s1.App.PendingSessions, stats.App.PendingSessions)
	require.Equal(s1.App.FinalSessions, stats.App.FinalSessions)
	require.Equal(s1.App.GeneratedKeys, stats.App.GeneratedKeys)
	require.Equal(s1.App.Version, stats.App.Version)

	for i := 1; i <= 10; i++ {
		err = testUpsertStats(ctx, node, k1)
		require.Nil(err)
		err = testUpsertStats(ctx, node, s1)
		require.Nil(err)
	}
	nks, err = node.store.ListNodeStats(ctx, NodeTypeKeeper)
	require.Nil(err)
	require.Len(nks, 11)
	for _, s := range nks {
		require.Equal(NodeTypeKeeper, s.Type)
	}
	nss, err = node.store.ListNodeStats(ctx, NodeTypeSigner)
	require.Nil(err)
	require.Len(nss, 11)
	for _, s := range nss {
		require.Equal(NodeTypeSigner, s.Type)
	}
}

func testUpsertStats(ctx context.Context, node *Node, s *StatsInfo) error {
	id := uuid.Must(uuid.NewV4()).String()
	return node.store.UpsertNodeStats(ctx, id, s.Type, s.String())
}

func testPublicKey(priv string) string {
	seed, _ := hex.DecodeString(priv)
	_, dk := btcec.PrivKeyFromBytes(seed)
	return hex.EncodeToString(dk.SerializeCompressed())
}

func testBuildNode(_ context.Context, require *require.Assertions, root string) *Node {
	f, _ := os.ReadFile("../config/example.toml")
	var conf struct {
		Observer *Configuration        `toml:"observer"`
		Keeper   *keeper.Configuration `toml:"keeper"`
	}
	err := toml.Unmarshal(f, &conf)
	require.Nil(err)

	conf.Keeper.StoreDir = root
	if !(strings.HasPrefix(conf.Keeper.StoreDir, "/tmp/") || strings.HasPrefix(conf.Keeper.StoreDir, "/var/folders")) {
		panic(root)
	}
	err = os.MkdirAll(conf.Keeper.StoreDir, os.ModePerm)
	require.Nil(err)
	kd, err := keeper.OpenSQLite3Store(conf.Keeper.StoreDir + "/keeper.sqlite3")
	require.Nil(err)

	// TODO should init a keeper node instead
	err = kd.Close()
	require.Nil(err)
	kd, err = keeper.OpenSQLite3ReadOnlyStore(conf.Keeper.StoreDir + "/keeper.sqlite3")
	require.Nil(err)

	conf.Observer.StoreDir = root
	if !(strings.HasPrefix(conf.Observer.StoreDir, "/tmp/") || strings.HasPrefix(conf.Observer.StoreDir, "/var/folders")) {
		panic(root)
	}
	db, err := OpenSQLite3Store(conf.Observer.StoreDir + "/observer.sqlite3")
	require.Nil(err)

	node := NewNode(db, kd, conf.Observer, conf.Keeper.MTG, nil)
	return node
}

func getMVMFactoryAssetAddress(assetId, symbol, name string, holder string) ec.Address {
	symbol, name = "safe"+symbol, name+" @ Mixin Safe"
	id := uuid.Must(uuid.FromString(assetId))
	args := math.U256Bytes(new(big.Int).SetBytes(id.Bytes()))
	args = append(args, holder...)
	args = append(args, symbol...)
	args = append(args, name...)
	salt := crypto.Keccak256(args)

	code, err := hex.DecodeString(testMVMAssetContractCode[2:])
	if err != nil {
		panic(err)
	}
	code = append(code, abi.PackAssetArguments(symbol, name)...)
	this, err := hex.DecodeString(testMVMFactoryAddress[2:])
	if err != nil {
		panic(err)
	}

	input := []byte{0xff}
	input = append(input, this...)
	input = append(input, math.U256Bytes(new(big.Int).SetBytes(salt))...)
	input = append(input, crypto.Keccak256(code)...)
	return ec.BytesToAddress(crypto.Keccak256(input))
}

const testMVMAssetContractCode = "0x60806040523480156200001157600080fd5b506040516200093038038062000930833981016040819052620000349162000133565b60036200004283826200022c565b5060026200005182826200022c565b5050336000908152602081905260409020600019905550620002f8565b634e487b7160e01b600052604160045260246000fd5b600082601f8301126200009657600080fd5b81516001600160401b0380821115620000b357620000b36200006e565b604051601f8301601f19908116603f01168101908282118183101715620000de57620000de6200006e565b81604052838152602092508683858801011115620000fb57600080fd5b600091505b838210156200011f578582018301518183018401529082019062000100565b600093810190920192909252949350505050565b600080604083850312156200014757600080fd5b82516001600160401b03808211156200015f57600080fd5b6200016d8683870162000084565b935060208501519150808211156200018457600080fd5b50620001938582860162000084565b9150509250929050565b600181811c90821680620001b257607f821691505b602082108103620001d357634e487b7160e01b600052602260045260246000fd5b50919050565b601f8211156200022757600081815260208120601f850160051c81016020861015620002025750805b601f850160051c820191505b8181101562000223578281556001016200020e565b5050505b505050565b81516001600160401b038111156200024857620002486200006e565b62000260816200025984546200019d565b84620001d9565b602080601f8311600181146200029857600084156200027f5750858301515b600019600386901b1c1916600185901b17855562000223565b600085815260208120601f198616915b82811015620002c957888601518255948401946001909101908401620002a8565b5085821015620002e85787850151600019600388901b60f8161c191681555b5050505050600190811b01905550565b61062880620003086000396000f3fe608060405234801561001057600080fd5b50600436106100935760003560e01c8063313ce56711610066578063313ce5671461010357806370a082311461011d57806395d89b4114610146578063a9059cbb1461014e578063dd62ed3e1461016157600080fd5b806306fdde0314610098578063095ea7b3146100b657806318160ddd146100d957806323b872dd146100f0575b600080fd5b6100a061019a565b6040516100ad9190610457565b60405180910390f35b6100c96100c43660046104c1565b610228565b60405190151581526020016100ad565b6100e260001981565b6040519081526020016100ad565b6100c96100fe3660046104eb565b61030d565b61010b601281565b60405160ff90911681526020016100ad565b6100e261012b366004610527565b6001600160a01b031660009081526020819052604090205490565b6100a0610324565b6100c961015c3660046104c1565b610331565b6100e261016f366004610549565b6001600160a01b03918216600090815260016020908152604080832093909416825291909152205490565b600280546101a79061057c565b80601f01602080910402602001604051908101604052809291908181526020018280546101d39061057c565b80156102205780601f106101f557610100808354040283529160200191610220565b820191906000526020600020905b81548152906001019060200180831161020357829003601f168201915b505050505081565b600081158061025857503360009081526001602090815260408083206001600160a01b0387168452909152902054155b6102a85760405162461bcd60e51b815260206004820152601f60248201527f617070726f7665206f6e2061206e6f6e2d7a65726f20616c6c6f77616e636500604482015260640160405180910390fd5b3360008181526001602090815260408083206001600160a01b03881680855290835292819020869055518581529192917f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925910160405180910390a35060015b92915050565b600061031a848484610347565b5060019392505050565b600380546101a79061057c565b600061033e3384846103aa565b50600192915050565b6001600160a01b038316600090815260016020908152604080832033845290915290205461037582826105cc565b6001600160a01b03851660009081526001602090815260408083203384529091529020556103a48484846103aa565b50505050565b6001600160a01b0383166000908152602081905260409020546103ce9082906105cc565b6001600160a01b0380851660009081526020819052604080822093909355908416815220546103fe9082906105df565b6001600160a01b038381166000818152602081815260409182902094909455518481529092918616917fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef910160405180910390a3505050565b600060208083528351808285015260005b8181101561048457858101830151858201604001528201610468565b506000604082860101526040601f19601f8301168501019250505092915050565b80356001600160a01b03811681146104bc57600080fd5b919050565b600080604083850312156104d457600080fd5b6104dd836104a5565b946020939093013593505050565b60008060006060848603121561050057600080fd5b610509846104a5565b9250610517602085016104a5565b9150604084013590509250925092565b60006020828403121561053957600080fd5b610542826104a5565b9392505050565b6000806040838503121561055c57600080fd5b610565836104a5565b9150610573602084016104a5565b90509250929050565b600181811c9082168061059057607f821691505b6020821081036105b057634e487b7160e01b600052602260045260246000fd5b50919050565b634e487b7160e01b600052601160045260246000fd5b81810381811115610307576103076105b6565b80820180821115610307576103076105b656fea264697066735822122084ca443d97b3271c715ed62fcad694ee7a1a98607b036f06e1a648531aeb1bc264736f6c63430008120033"
