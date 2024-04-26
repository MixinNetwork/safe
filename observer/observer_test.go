package observer

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
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

	fvb, err := bitcoin.EstimateAvgFee(keeper.SafeChainBitcoin, node.conf.BitcoinRPC)
	require.Nil(err)
	require.Greater(fvb, int64(10))
	require.Less(fvb, int64(500))
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
