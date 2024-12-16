package computer

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/safe/saver"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/pelletier/go-toml"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

var sequence uint64 = 5000000

func TestComputer(t *testing.T) {
	require := require.New(t)
	ctx, nodes, _, _ := testPrepare(require)

	testObserverRequestGenerateKeys(ctx, require, nodes)

}

func testObserverRequestGenerateKeys(ctx context.Context, require *require.Assertions, nodes []*Node) {
	node := nodes[0]
	batch := byte(8)
	id := uuid.Must(uuid.NewV4()).String()
	var sessionId string

	for i, node := range nodes {
		out := testBuildObserverRequest(node, id, OperationTypeKeygenInput, []byte{batch})
		if i == 0 {
			sessionId = out.OutputId
		}
		testStep(ctx, require, node, out)
		sessions, err := node.store.ListPreparedSessions(ctx, 500)
		require.Nil(err)
		require.Len(sessions, 8)
	}

	members := node.GetMembers()
	threshold := node.conf.MTG.Genesis.Threshold
	sessionId = common.UniqueId(sessionId, fmt.Sprintf("%8d", 8-1))
	sessionId = common.UniqueId(sessionId, fmt.Sprintf("MTG:%v:%d", members, threshold))
	testWaitOperation(ctx, node, sessionId)
	count, err := node.store.CountSpareKeys(ctx)
	require.Nil(err)
	require.Equal(8, count)
	sessions, err := node.store.ListPreparedSessions(ctx, 500)
	require.Nil(err)
	require.Len(sessions, 0)

}

func testBuildObserverRequest(node *Node, id string, action byte, extra []byte) *mtg.Action {
	sequence += 10

	memo := []byte{action}
	memo = append(memo, extra...)
	memoStr := mtg.EncodeMixinExtraBase64(node.conf.AppId, memo)
	memoStr = hex.EncodeToString([]byte(memoStr))
	timestamp := time.Now()
	return &mtg.Action{
		UnifiedOutput: mtg.UnifiedOutput{
			OutputId:           common.UniqueId(id, "output"),
			TransactionHash:    crypto.Sha256Hash([]byte(id)).String(),
			AppId:              node.conf.AppId,
			Senders:            []string{string(node.id)},
			AssetId:            node.conf.ObserverAssetId,
			Extra:              memoStr,
			Amount:             decimal.New(1, 1),
			SequencerCreatedAt: timestamp,
			Sequence:           sequence,
		},
	}
}

func testStep(ctx context.Context, require *require.Assertions, node *Node, out *mtg.Action) {
	txs1, asset := node.ProcessOutput(ctx, out)
	require.Equal("", asset)
	timestamp, err := node.timestamp(ctx)
	require.Nil(err)
	require.Equal(out.Sequence, timestamp)
	req, err := node.store.ReadPendingRequest(ctx)
	require.Nil(err)
	require.Nil(req)
	req, err = node.store.ReadLatestRequest(ctx)
	require.Nil(err)
	ar, handled, err := node.store.ReadActionResult(ctx, out.OutputId, req.Id)
	require.Nil(err)
	require.True(handled)
	require.Equal("", ar.Compaction)
	txs3, asset := node.ProcessOutput(ctx, out)
	require.Equal("", asset)
	for i, tx1 := range txs1 {
		tx2 := ar.Transactions[i]
		tx3 := txs3[i]
		tx1.AppId = out.AppId
		tx2.AppId = out.AppId
		tx3.AppId = out.AppId
		tx1.Sequence = out.Sequence
		tx2.Sequence = out.Sequence
		tx3.Sequence = out.Sequence
		id := common.UniqueId(tx1.OpponentAppId, "test")
		tx1.OpponentAppId = id
		tx2.OpponentAppId = id
		tx3.OpponentAppId = id
		require.True(tx1.Equal(tx2))
		require.True(tx2.Equal(tx3))
	}
}

func testPrepare(require *require.Assertions) (context.Context, []*Node, []*mtg.SQLite3Store, *saver.SQLite3Store) {
	logger.SetLevel(logger.INFO)
	ctx := context.Background()
	ctx = common.EnableTestEnvironment(ctx)

	saverStore, port := testStartSaver(require)

	nodes := make([]*Node, 4)
	mds := make([]*mtg.SQLite3Store, 4)
	for i := 0; i < 4; i++ {
		dir := fmt.Sprintf("safe-signer-test-%d", i)
		root, err := os.MkdirTemp("", dir)
		require.Nil(err)
		nodes[i], mds[i] = testBuildNode(ctx, require, root, i, saverStore, port)
		testInitOutputs(ctx, require, mds[i], nodes[i].conf)
	}

	network := newTestNetwork(nodes[0].GetPartySlice())
	for i := 0; i < 4; i++ {
		nodes[i].network = network
		ctx = context.WithValue(ctx, partyContextKey, string(nodes[i].id))
		go network.mtgLoop(ctx, nodes[i])
		go nodes[i].loopInitialSessions(ctx)
		go nodes[i].loopPreparedSessions(ctx)
		go nodes[i].loopPendingSessions(ctx)
		go nodes[i].acceptIncomingMessages(ctx)
	}

	return ctx, nodes, mds, saverStore
}

func testBuildNode(ctx context.Context, require *require.Assertions, root string, i int, saverStore *saver.SQLite3Store, port int) (*Node, *mtg.SQLite3Store) {
	f, _ := os.ReadFile("../config/example.toml")
	var conf struct {
		Computer *Configuration `toml:"computer"`
	}
	err := toml.Unmarshal(f, &conf)
	require.Nil(err)

	conf.Computer.StoreDir = root
	conf.Computer.MTG.App.AppId = conf.Computer.MTG.Genesis.Members[i]
	conf.Computer.MTG.GroupSize = 1
	conf.Computer.SaverAPI = fmt.Sprintf("http://localhost:%d", port)

	seed := crypto.Sha256Hash([]byte(conf.Computer.MTG.App.AppId))
	priv := crypto.NewKeyFromSeed(append(seed[:], seed[:]...))
	conf.Computer.SaverKey = priv.String()
	err = saverStore.WriteNodePublicKey(ctx, conf.Computer.MTG.App.AppId, priv.Public().String())
	require.Nil(err)

	if !(strings.HasPrefix(conf.Computer.StoreDir, "/tmp/") || strings.HasPrefix(conf.Computer.StoreDir, "/var/folders")) {
		panic(root)
	}
	kd, err := store.OpenSQLite3Store(conf.Computer.StoreDir + "/mpc.sqlite3")
	require.Nil(err)

	md, err := mtg.OpenSQLite3Store(conf.Computer.StoreDir + "/mtg.sqlite3")
	require.Nil(err)
	group, err := mtg.BuildGroup(ctx, md, conf.Computer.MTG)
	require.Nil(err)
	group.EnableDebug()

	node := NewNode(kd, group, nil, conf.Computer, nil)
	group.AttachWorker(node.conf.AppId, node)
	return node, md
}

func testInitOutputs(ctx context.Context, require *require.Assertions, md *mtg.SQLite3Store, conf *Configuration) {
	for i := range 100 {
		_, err := testWriteOutput(ctx, md, conf.AppId, conf.AssetId, "", uint64(sequence), decimal.NewFromInt(1))
		require.Nil(err)
		sequence += uint64(i + 1)
	}
	for i := range 100 {
		_, err := testWriteOutput(ctx, md, conf.AppId, conf.ObserverAssetId, "", uint64(sequence), decimal.NewFromInt(1))
		require.Nil(err)
		sequence += uint64(i + 1)
	}
	for i := range 100 {
		_, err := testWriteOutput(ctx, md, conf.AppId, mtg.StorageAssetId, "", uint64(sequence), decimal.NewFromInt(1))
		require.Nil(err)
		sequence += uint64(i + 1)
	}
}

func testWriteOutput(ctx context.Context, db *mtg.SQLite3Store, appId, assetId, extra string, sequence uint64, amount decimal.Decimal) (*mtg.UnifiedOutput, error) {
	id := uuid.Must(uuid.NewV4())
	output := &mtg.UnifiedOutput{
		OutputId:           id.String(),
		AppId:              appId,
		AssetId:            assetId,
		Amount:             amount,
		Sequence:           sequence,
		SequencerCreatedAt: time.Now(),
		TransactionHash:    crypto.Sha256Hash(id.Bytes()).String(),
		State:              mtg.SafeUtxoStateUnspent,
		Extra:              extra,
	}
	err := db.WriteAction(ctx, output, mtg.ActionStateDone)
	return output, err
}
