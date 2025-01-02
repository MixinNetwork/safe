package computer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	mc "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/safe/saver"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/gagliardetto/solana-go"
	"github.com/gofrs/uuid/v5"
	"github.com/pelletier/go-toml"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

var sequence uint64 = 5000000

func TestComputer(t *testing.T) {
	require := require.New(t)
	ctx, nodes, mds, _ := testPrepare(require)

	testObserverRequestGenerateKeys(ctx, require, nodes)
	testObserverRequestCreateNonceAccount(ctx, require, nodes)
	testObserverRequestInitMpcKey(ctx, require, nodes)

	user := testUserRequestAddUsers(ctx, require, nodes)
	testUserRequestSystemCall(ctx, require, nodes, mds, user)
}

func testUserRequestSystemCall(ctx context.Context, require *require.Assertions, nodes []*Node, mds []*mtg.SQLite3Store, user *store.User) {
	conf := nodes[0].conf

	sequence += 10
	_, err := testWriteOutputForNodes(ctx, mds, conf.AppId, common.SafeLitecoinChainId, "a8eed784060b200ea7f417309b12a33ced8344c24f5cdbe0237b7fc06125f459", "", sequence, decimal.NewFromInt(1000000))
	require.Nil(err)
	sequence += 10
	_, err = testWriteOutputForNodes(ctx, mds, conf.AppId, common.SafeSolanaChainId, "01c43005fd06e0b8f06a0af04faf7530331603e352a11032afd0fd9dbd84e8ee", "", sequence, decimal.NewFromInt(5000000))
	require.Nil(err)

	id := uuid.Must(uuid.NewV4()).String()
	hash := "d3b2db9339aee4acb39d0809fc164eb7091621400a9a3d64e338e6ffd035d32f"
	extra := user.IdBytes()
	extra = append(extra, common.DecodeHexOrPanic("0002000205cdc56c8d087a301b21144b2ab5e1286b50a5d941ee02f62488db0308b943d2d64375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295bad4af79952644bd80881b3934b3e278ad2f4eeea3614e1c428350d905eac4ec06a7d517192c568ee08a845f73d29788cf035c3145b21ab344d8062ea94000000000000000000000000000000000000000000000000000000000000000000000dcc859c62859a93c7ca37d6f180d63ba1f1ccadc68373b6605c4358bd77983060204030203000404000000040201010c0200000040420f0000000000")...)
	for _, node := range nodes {
		out := testBuildUserRequest(node, id, hash, OperationTypeSystemCall, extra)
		testStep(ctx, require, node, out)
		call, err := node.store.ReadSystemCallByRequestId(ctx, out.OutputId, common.RequestStateInitial)
		require.Nil(err)
		require.Equal(out.OutputId, call.RequestId)
		require.Equal(out.OutputId, call.Superior)
		require.Equal(store.CallTypeMain, call.Type)
		require.Equal(user.NonceAccount, call.NonceAccount)
		require.Equal(user.Public, call.Public)
		require.Len(call.GetWithdrawalIds(), 1)
		require.False(call.WithdrawedAt.Valid)
		require.False(call.Signature.Valid)
		require.False(call.RequestSignerAt.Valid)
	}
}

func testUserRequestAddUsers(ctx context.Context, require *require.Assertions, nodes []*Node) *store.User {
	start := big.NewInt(0).Add(store.StartUserId, big.NewInt(1))
	var user *store.User
	for _, node := range nodes {
		id := uuid.Must(uuid.NewV4())
		seed := id.Bytes()
		seed = append(seed, id.Bytes()...)
		seed = append(seed, id.Bytes()...)
		seed = append(seed, id.Bytes()...)
		mix := mc.NewAddressFromSeed(seed)
		out := testBuildUserRequest(node, id.String(), "", OperationTypeAddUser, []byte(mix.String()))
		testStep(ctx, require, node, out)
		user1, err := node.store.ReadUserByAddress(ctx, mix.String())
		require.Nil(err)
		require.Equal(mix.String(), user1.Address)
		require.Equal(start.String(), user1.UserId)
		require.Equal("4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295", user1.Public)
		require.NotEqual("", user1.NonceAccount)
		user = user1
		count, err := node.store.CountSpareKeys(ctx)
		require.Nil(err)
		require.Equal(8, count)
		count, err = node.store.CountSpareNonceAccounts(ctx)
		require.Nil(err)
		require.Equal(3, count)

		id = uuid.Must(uuid.NewV4())
		seed = id.Bytes()
		seed = append(seed, id.Bytes()...)
		seed = append(seed, id.Bytes()...)
		seed = append(seed, id.Bytes()...)
		mix = mc.NewAddressFromSeed(seed)
		out = testBuildUserRequest(node, id.String(), "", OperationTypeAddUser, []byte(mix.String()))
		testStep(ctx, require, node, out)
		user2, err := node.store.ReadUserByAddress(ctx, mix.String())
		require.Nil(err)
		require.Equal(mix.String(), user2.Address)
		require.Equal(big.NewInt(0).Add(start, big.NewInt(1)).String(), user2.UserId)
		require.NotEqual("", user1.Public)
		require.NotEqual("", user1.NonceAccount)
		count, err = node.store.CountSpareKeys(ctx)
		require.Nil(err)
		require.Equal(7, count)
		count, err = node.store.CountSpareNonceAccounts(ctx)
		require.Nil(err)
		require.Equal(2, count)
	}
	return user
}

func testObserverRequestCreateNonceAccount(ctx context.Context, require *require.Assertions, nodes []*Node) {
	as := [][2]string{
		{"DaJw3pa9rxr25AT1HnQnmPvwS4JbnwNvQbNLm8PJRhqV", "FrqtK1eTYLJtR6mGNaBWF6qyfpjTqk1DJaAQdAm31Xc1"},
		testGenerateRandNonceAccount(require),
		testGenerateRandNonceAccount(require),
		testGenerateRandNonceAccount(require),
	}
	addr := solana.MustPublicKeyFromBase58(as[0][0])

	for _, node := range nodes {
		count, err := node.store.CountSpareNonceAccounts(ctx)
		require.Nil(err)
		require.Equal(0, count)

		for _, nonce := range as {
			address := solana.MustPublicKeyFromBase58(nonce[0])
			hash := solana.MustHashFromBase58(nonce[1])
			extra := address.Bytes()
			extra = append(extra, hash[:]...)

			id := uuid.Must(uuid.NewV4()).String()
			out := testBuildObserverRequest(node, id, OperationTypeCreateNonce, extra)
			testStep(ctx, require, node, out)
			account, err := node.store.ReadNonceAccount(ctx, address.String())
			require.Nil(err)
			require.Equal(hash.String(), account.Hash)
		}

		hash := solana.MustHashFromBase58("25DfFJbUsDMR7rYpieHhK7diWB1EuWkv5nB3F6CzNFTR")
		extra := addr.Bytes()
		extra = append(extra, hash[:]...)
		id := uuid.Must(uuid.NewV4()).String()
		out := testBuildObserverRequest(node, id, OperationTypeCreateNonce, extra)
		testStep(ctx, require, node, out)
		account, err := node.store.ReadNonceAccount(ctx, addr.String())
		require.Nil(err)
		require.Equal(hash.String(), account.Hash)

		count, err = node.store.CountSpareNonceAccounts(ctx)
		require.Nil(err)
		require.Equal(4, count)
	}
}

func testObserverRequestInitMpcKey(ctx context.Context, require *require.Assertions, nodes []*Node) {
	for _, node := range nodes {
		initialized, err := node.store.CheckMpcKeyInitialized(ctx)
		require.Nil(err)
		require.False(initialized)

		key, err := node.store.ReadFirstGeneratedKey(ctx)
		require.Nil(err)
		require.Equal("fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b", key)

		id := common.UniqueId(key, "mpc init key")
		extra := common.DecodeHexOrPanic(key)
		out := testBuildObserverRequest(node, id, OperationTypeInitMPCKey, extra)
		testStep(ctx, require, node, out)

		mtg, err := node.store.ReadUser(ctx, store.MPCUserId)
		require.Nil(err)
		require.Equal("fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b", mtg.Public)
		require.Equal("", mtg.NonceAccount)

		initialized, err = node.store.CheckMpcKeyInitialized(ctx)
		require.Nil(err)
		require.True(initialized)
	}
}

func testObserverRequestGenerateKeys(ctx context.Context, require *require.Assertions, nodes []*Node) {
	node := nodes[0]
	batch := byte(8)
	id := uuid.Must(uuid.NewV4()).String()
	var sessionId string

	for i, node := range nodes {
		count, err := node.store.CountSpareKeys(ctx)
		require.Nil(err)
		require.Equal(2, count)

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
	for _, node := range nodes {
		testWaitOperation(ctx, node, sessionId)
	}
	time.Sleep(5 * time.Second)
	for _, node := range nodes {
		count, err := node.store.CountSpareKeys(ctx)
		require.Nil(err)
		require.Equal(10, count)

		sessions, err := node.store.ListPreparedSessions(ctx, 500)
		require.Nil(err)
		require.Len(sessions, 0)
		sessions, err = node.store.ListPendingSessions(ctx, 500)
		require.Nil(err)
		require.Len(sessions, 0)

		key, err := node.store.GetSpareKey(ctx)
		require.Nil(err)
		require.Equal("fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b", key.Public)
	}
}

func testBuildUserRequest(node *Node, id, hash string, action byte, extra []byte) *mtg.Action {
	sequence += 10
	id = common.UniqueId(id, "output")
	if hash == "" {
		hash = crypto.Sha256Hash([]byte(id)).String()
	}

	memo := []byte{action}
	memo = append(memo, extra...)
	memoStr := testEncodeMixinExtra(node.conf.AppId, memo)
	memoStr = hex.EncodeToString([]byte(memoStr))
	timestamp := time.Now()
	return &mtg.Action{
		UnifiedOutput: mtg.UnifiedOutput{
			OutputId:           id,
			TransactionHash:    hash,
			AppId:              node.conf.AppId,
			Senders:            []string{string(node.id)},
			AssetId:            mtg.StorageAssetId,
			Extra:              memoStr,
			Amount:             decimal.New(1, 1),
			SequencerCreatedAt: timestamp,
			Sequence:           sequence,
		},
	}
}

func testBuildObserverRequest(node *Node, id string, action byte, extra []byte) *mtg.Action {
	sequence += 10
	id = common.UniqueId(id, "output")
	memo := []byte{action}
	memo = append(memo, extra...)
	memoStr := mtg.EncodeMixinExtraBase64(node.conf.AppId, memo)
	memoStr = hex.EncodeToString([]byte(memoStr))
	timestamp := time.Now()
	return &mtg.Action{
		UnifiedOutput: mtg.UnifiedOutput{
			OutputId:           id,
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

func testBuildSignerRequest(node *Node, id string, action byte, extra []byte) *mtg.Action {
	sequence += 10
	id = common.UniqueId(id, "output")
	memo := []byte{action}
	memo = append(memo, extra...)
	memoStr := mtg.EncodeMixinExtraBase64(node.conf.AppId, memo)
	memoStr = hex.EncodeToString([]byte(memoStr))
	timestamp := time.Now()
	return &mtg.Action{
		UnifiedOutput: mtg.UnifiedOutput{
			OutputId:           id,
			TransactionHash:    crypto.Sha256Hash([]byte(id)).String(),
			AppId:              node.conf.AppId,
			Senders:            []string{string(node.id)},
			AssetId:            node.conf.AssetId,
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
	txs2 := ar.Transactions
	txs3, asset := node.ProcessOutput(ctx, out)
	require.Equal("", asset)
	for i, tx1 := range txs1 {
		tx2 := txs2[i]
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
	}
	testInitOutputs(ctx, require, nodes, mds)

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

	testFROSTPrepareKeys(ctx, require, nodes, testFROSTKeys1, "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b")
	testFROSTPrepareKeys(ctx, require, nodes, testFROSTKeys2, "4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295")

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

func testInitOutputs(ctx context.Context, require *require.Assertions, nodes []*Node, mds []*mtg.SQLite3Store) {
	start := sequence - 1
	conf := nodes[0].conf
	for i := range 100 {
		_, err := testWriteOutputForNodes(ctx, mds, conf.AppId, conf.AssetId, "", "", uint64(sequence), decimal.NewFromInt(1))
		require.Nil(err)
		sequence += uint64(i + 1)
	}
	for i := range 100 {
		_, err := testWriteOutputForNodes(ctx, mds, conf.AppId, conf.ObserverAssetId, "", "", uint64(sequence), decimal.NewFromInt(1))
		require.Nil(err)
		sequence += uint64(i + 1)
	}
	for i := range 100 {
		_, err := testWriteOutputForNodes(ctx, mds, conf.AppId, mtg.StorageAssetId, "", "", uint64(sequence), decimal.NewFromInt(1))
		require.Nil(err)
		sequence += uint64(i + 1)
	}
	for _, node := range nodes {
		os := node.group.ListOutputsForAsset(ctx, conf.AppId, conf.AssetId, start, sequence, mtg.SafeUtxoStateUnspent, 500)
		require.Len(os, 100)
		os = node.group.ListOutputsForAsset(ctx, conf.AppId, conf.ObserverAssetId, start, sequence, mtg.SafeUtxoStateUnspent, 500)
		require.Len(os, 100)
		os = node.group.ListOutputsForAsset(ctx, conf.AppId, mtg.StorageAssetId, start, sequence, mtg.SafeUtxoStateUnspent, 500)
		require.Len(os, 100)
	}
}

func testWriteOutputForNodes(ctx context.Context, dbs []*mtg.SQLite3Store, appId, assetId, hash, extra string, sequence uint64, amount decimal.Decimal) (*mtg.UnifiedOutput, error) {
	id := uuid.Must(uuid.NewV4())
	if hash == "" {
		hash = crypto.Sha256Hash(id.Bytes()).String()
	}
	output := &mtg.UnifiedOutput{
		OutputId:           id.String(),
		AppId:              appId,
		AssetId:            assetId,
		Amount:             amount,
		Sequence:           sequence,
		SequencerCreatedAt: time.Now(),
		TransactionHash:    hash,
		State:              mtg.SafeUtxoStateUnspent,
		Extra:              extra,
	}
	for _, db := range dbs {
		err := db.WriteAction(ctx, output, mtg.ActionStateDone)
		if err != nil {
			return nil, err
		}
	}
	return output, nil
}

func testFROSTPrepareKeys(ctx context.Context, require *require.Assertions, nodes []*Node, testKeys map[party.ID]string, public string) {
	for _, node := range nodes {
		parts := strings.Split(testKeys[node.id], ";")
		pub, share := parts[0], parts[1]
		conf, _ := hex.DecodeString(share)
		require.Equal(public, pub)
		id := common.UniqueId("prepare", public)
		err := node.store.TestWriteKey(ctx, id, pub, conf, false)
		require.Nil(err)
	}
}

func testGenerateRandNonceAccount(require *require.Assertions) [2]string {
	key1, err := solana.NewRandomPrivateKey()
	require.Nil(err)
	key2, err := solana.NewRandomPrivateKey()
	require.Nil(err)
	return [2]string{key1.PublicKey().String(), solana.HashFromBytes(key2.PublicKey().Bytes()).String()}
}

func testEncodeMixinExtra(appId string, extra []byte) string {
	gid, err := uuid.FromString(appId)
	if err != nil {
		panic(err)
	}
	data := gid.Bytes()
	data = append(data, extra...)
	s := base64.RawURLEncoding.EncodeToString(data)
	return s
}
