package observer

import (
	"context"
	"encoding/hex"
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
	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

const (
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
	require.Greater(fvb, int64(10))
	require.Less(fvb, int64(500))

	err = node.store.WriteAccountProposalIfNotExists(ctx, testReceiverAddress, time.Now())
	require.Nil(err)
	f, err := node.store.CheckAccountProposed(ctx, testReceiverAddress)
	require.Nil(err)
	require.True(f)
	a, err := node.store.ReadAccount(ctx, testReceiverAddress)
	require.Nil(err)
	require.Equal(testReceiverAddress, a.Address)
	require.False(a.Approved)
	require.Equal("", a.Signature)
	as, err := node.store.ListProposedAccountsWithSig(ctx)
	require.Nil(err)
	require.Len(as, 0)
	err = node.store.SaveAccountApprovalSignature(ctx, testReceiverAddress, "signature")
	require.Nil(err)
	as, err = node.store.ListProposedAccountsWithSig(ctx)
	require.Nil(err)
	require.Len(as, 1)
	err = node.store.MarkAccountApproved(ctx, testReceiverAddress)
	require.Nil(err)
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

	abi.TestInitFactoryContractAddress(ctx, node.conf.MVMFactoryAddress)
	bond := abi.GetMVMFactoryAssetAddress(assetId, asset.Symbol, asset.Name, holder)
	bondId := ethereum.GenerateAssetId(common.SafeChainMVM, strings.ToLower(bond.Hex()))
	require.Equal(testMVMBondAssetId, bondId)

	abi.TestInitFactoryContractAddress(ctx, node.conf.PolygonFactoryAddress)
	err = abi.GetOrDeployFactoryAsset(ctx, node.conf.PolygonRPC, os.Getenv("MVM_DEPLOYER"), assetId, asset.Symbol, asset.Name, testReceiverAddress, holder)
	require.Nil(err)

	bond = abi.GetFactoryAssetAddress(testReceiverAddress, assetId, asset.Symbol, asset.Name, holder)
	bondId = ethereum.GenerateAssetId(common.SafeChainPolygon, strings.ToLower(bond.Hex()))
	require.Equal(testPolygonBondAssetId, bondId)
}

func testPublicKey(priv string) string {
	seed, _ := hex.DecodeString(priv)
	_, dk := btcec.PrivKeyFromBytes(seed)
	return hex.EncodeToString(dk.SerializeCompressed())
}

func testBuildNode(ctx context.Context, require *require.Assertions, root string) *Node {
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
