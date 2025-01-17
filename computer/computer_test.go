package computer

import (
	"context"
	"encoding/base64"
	"encoding/binary"
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
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
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

	testObserverRequestGenerateKey(ctx, require, nodes)
	testObserverRequestCreateNonceAccount(ctx, require, nodes)
	testObserverSetPriceParams(ctx, require, nodes)

	user := testUserRequestAddUsers(ctx, require, nodes)
	call := testUserRequestSystemCall(ctx, require, nodes, mds, user)
	testConfirmWithdrawal(ctx, require, nodes, call)
	sub := testObserverCreateSubCall(ctx, require, nodes, call)
	testObserverConfirmSubCall(ctx, require, nodes, sub)
	testObserverConfirmMainCall(ctx, require, nodes, call)
	postprocess := testObserverCreatePostprocessCall(ctx, require, nodes, call)
	testObserverConfirmPostprocessCall(ctx, require, nodes, postprocess)
}

func testObserverConfirmPostprocessCall(ctx context.Context, require *require.Assertions, nodes []*Node, sub *store.SystemCall) {
	signature := solana.MustSignatureFromBase58("5s3UBMymdgDHwYvuaRdq9SLq94wj5xAgYEsDDB7TQwwuLy1TTYcSf6rF4f2fDfF7PnA9U75run6r1pKm9K1nusCR")
	hash := solana.MustHashFromBase58("6c8hGTPpTd4RMbYyM3wQgnwxZbajKhovhfDgns6bvmrX")

	id := uuid.Must(uuid.NewV4()).String()
	extra := []byte{FlagConfirmCallSuccess}
	extra = append(extra, signature[:]...)
	extra = append(extra, hash[:]...)

	for _, node := range nodes {
		out := testBuildObserverRequest(node, id, OperationTypeConfirmCall, extra)
		testStep(ctx, require, node, out)

		sub, err := node.store.ReadSystemCallByRequestId(ctx, sub.RequestId, common.RequestStateDone)
		require.Nil(err)
		require.NotNil(sub)
		nonce, err := node.store.ReadNonceAccount(ctx, sub.NonceAccount)
		require.Nil(err)
		require.Equal(hash.String(), nonce.Hash)

		call, err := node.store.ReadSystemCallByRequestId(ctx, sub.Superior, common.RequestStateDone)
		require.Nil(err)
		require.NotNil(call)

		ar, _, err := node.store.ReadActionResult(ctx, id, id)
		require.Nil(err)
		require.Len(ar.Transactions, 1)
		require.Equal(common.SafeLitecoinChainId, ar.Transactions[0].AssetId)
	}
}

func testObserverCreatePostprocessCall(ctx context.Context, require *require.Assertions, nodes []*Node, call *store.SystemCall) *store.SystemCall {
	nonce, err := nodes[0].store.ReadNonceAccount(ctx, call.NonceAccount)
	require.Nil(err)
	stx := nodes[0].burnRestTokens(ctx, call, solanaApp.PublicKeyFromEd25519Public(call.Public), nonce)
	require.NotNil(stx)
	raw, err := stx.MarshalBinary()
	require.Nil(err)
	ref := crypto.Sha256Hash(raw)

	id := uuid.Must(uuid.NewV4()).String()
	var extra []byte
	extra = append(extra, uuid.Must(uuid.FromString(call.RequestId)).Bytes()...)
	extra = append(extra, solana.MustPublicKeyFromBase58(call.NonceAccount).Bytes()...)
	extra = append(extra, ref[:]...)

	for _, node := range nodes {
		err = node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(raw))
		require.Nil(err)
		out := testBuildObserverRequest(node, id, OperationTypeCreateSubCall, extra)
		testStep(ctx, require, node, out)

		sub, err := node.store.ReadSystemCallByRequestId(ctx, id, common.RequestStatePending)
		require.Nil(err)
		require.Equal(id, sub.RequestId)
		require.Equal(call.RequestId, sub.Superior)
		require.Equal(store.CallTypePostProcess, sub.Type)
		require.Len(sub.GetWithdrawalIds(), 0)
		require.True(sub.WithdrawedAt.Valid)
		require.False(sub.Signature.Valid)
		require.False(sub.RequestSignerAt.Valid)
	}

	tid := common.UniqueId(id, time.Time{}.String())
	extra = uuid.Must(uuid.FromString(id)).Bytes()
	for _, node := range nodes {
		out := testBuildObserverRequest(node, tid, OperationTypeSignInput, extra)
		testStep(ctx, require, node, out)
		session, err := node.store.ReadSession(ctx, out.OutputId)
		require.Nil(err)
		require.NotNil(session)
	}
	for _, node := range nodes {
		testWaitOperation(ctx, node, tid)
	}
	for {
		s, err := nodes[0].store.ReadSystemCallByRequestId(ctx, id, common.RequestStatePending)
		require.Nil(err)
		if s != nil && s.Signature.Valid {
			return s
		}
	}
}

func testObserverConfirmMainCall(ctx context.Context, require *require.Assertions, nodes []*Node, call *store.SystemCall) {
	signature := solana.MustSignatureFromBase58("39XBTQ7v6874uQb3vpF4zLe2asgNXjoBgQDkNiWya9ZW7UuG6DgY7kP4DFTRaGUo48NZF4qiZFGs1BuWJyCzRLtW")
	hash := solana.MustHashFromBase58("E9esweXgoVfahhRvpWR4kefZXR54qd82ZGhVTbzQtCoX")

	id := uuid.Must(uuid.NewV4()).String()
	extra := []byte{FlagConfirmCallSuccess}
	extra = append(extra, signature[:]...)
	extra = append(extra, hash[:]...)

	for _, node := range nodes {
		out := testBuildObserverRequest(node, id, OperationTypeConfirmCall, extra)
		testStep(ctx, require, node, out)
		sub, err := node.store.ReadSystemCallByRequestId(ctx, call.RequestId, common.RequestStateDone)
		require.Nil(err)
		require.NotNil(sub)
		nonce, err := node.store.ReadNonceAccount(ctx, call.NonceAccount)
		require.Nil(err)
		require.Equal(hash.String(), nonce.Hash)
		require.True(nonce.UserId.Valid)
	}
}

func testObserverConfirmSubCall(ctx context.Context, require *require.Assertions, nodes []*Node, sub *store.SystemCall) {
	signature := solana.MustSignatureFromBase58("2tPHv7kbUeHRWHgVKKddQqXnjDhuX84kTyCvRy1BmCM4m4Fkq4vJmNAz8A7fXqckrSNRTAKuPmAPWnzr5T7eCChb")
	hash := solana.MustHashFromBase58("6c8hGTPpTd4RMbYyM3wQgnwxZbajKhovhfDgns6bvmrX")

	id := uuid.Must(uuid.NewV4()).String()
	extra := []byte{FlagConfirmCallSuccess}
	extra = append(extra, signature[:]...)
	extra = append(extra, hash[:]...)

	var callId string
	for _, node := range nodes {
		out := testBuildObserverRequest(node, id, OperationTypeConfirmCall, extra)
		testStep(ctx, require, node, out)

		sub, err := node.store.ReadSystemCallByRequestId(ctx, sub.RequestId, common.RequestStateDone)
		require.Nil(err)
		require.NotNil(sub)
		nonce, err := node.store.ReadNonceAccount(ctx, sub.NonceAccount)
		require.Nil(err)
		require.Equal(hash.String(), nonce.Hash)
		require.False(nonce.CallId.Valid)
		require.False(nonce.UserId.Valid)

		call, err := node.store.ReadSystemCallByRequestId(ctx, sub.Superior, common.RequestStatePending)
		require.Nil(err)
		require.NotNil(call)
		callId = sub.Superior
	}

	tid := common.UniqueId(callId, time.Time{}.String())
	extra = uuid.Must(uuid.FromString(callId)).Bytes()
	for _, node := range nodes {
		out := testBuildObserverRequest(node, tid, OperationTypeSignInput, extra)
		testStep(ctx, require, node, out)
		session, err := node.store.ReadSession(ctx, out.OutputId)
		require.Nil(err)
		require.NotNil(session)
	}
	for _, node := range nodes {
		testWaitOperation(ctx, node, tid)
	}
	for {
		s, err := nodes[0].store.ReadSystemCallByRequestId(ctx, callId, common.RequestStatePending)
		require.Nil(err)
		if s != nil && s.Signature.Valid {
			fmt.Println(s.Signature.String)
			return
		}
	}
}

func testObserverCreateSubCall(ctx context.Context, require *require.Assertions, nodes []*Node, call *store.SystemCall) *store.SystemCall {
	node := nodes[0]
	nonce, err := node.store.ReadSpareNonceAccount(ctx)
	require.Nil(err)
	require.Equal("7ipVMFwwgbvyum7yniEHrmxtbcpq6yVEY8iybr7vwsqC", nonce.Address)
	stx, as := node.transferOrMintTokens(ctx, call, nonce)
	require.NotNil(stx)
	require.Len(as, 1)
	raw, err := stx.MarshalBinary()
	require.Nil(err)
	ref := crypto.Sha256Hash(raw)
	mtg, err := node.store.ReadUser(ctx, store.MPCUserId)
	require.Nil(err)

	id := uuid.Must(uuid.NewV4()).String()
	var extra []byte
	extra = append(extra, uuid.Must(uuid.FromString(call.RequestId)).Bytes()...)
	extra = append(extra, nonce.Account().Address.Bytes()...)
	extra = append(extra, ref[:]...)
	for _, asset := range as {
		extra = append(extra, uuid.Must(uuid.FromString(asset.AssetId)).Bytes()...)
		extra = append(extra, solana.MustPublicKeyFromBase58(asset.Address).Bytes()...)
	}

	for _, node := range nodes {
		err = node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(raw))
		require.Nil(err)
		out := testBuildObserverRequest(node, id, OperationTypeCreateSubCall, extra)
		testStep(ctx, require, node, out)

		sub, err := node.store.ReadSystemCallByRequestId(ctx, id, common.RequestStatePending)
		require.Nil(err)
		require.Equal(id, sub.RequestId)
		require.Equal(call.RequestId, sub.Superior)
		require.Equal(store.CallTypePrepare, sub.Type)
		require.Equal(nonce.Address, sub.NonceAccount)
		require.Equal(mtg.Public, sub.Public)
		require.Len(sub.GetWithdrawalIds(), 0)
		require.True(sub.WithdrawedAt.Valid)
		require.False(sub.Signature.Valid)
		require.False(sub.RequestSignerAt.Valid)
	}

	tid := common.UniqueId(id, time.Time{}.String())
	extra = uuid.Must(uuid.FromString(id)).Bytes()
	for _, node := range nodes {
		out := testBuildObserverRequest(node, tid, OperationTypeSignInput, extra)
		testStep(ctx, require, node, out)
		session, err := node.store.ReadSession(ctx, out.OutputId)
		require.Nil(err)
		require.NotNil(session)
	}
	for _, node := range nodes {
		testWaitOperation(ctx, node, tid)
	}
	for {
		s, err := node.store.ReadSystemCallByRequestId(ctx, id, common.RequestStatePending)
		require.Nil(err)
		if s != nil && s.Signature.Valid {
			return s
		}
	}
}

func testConfirmWithdrawal(ctx context.Context, require *require.Assertions, nodes []*Node, call *store.SystemCall) {
	tid := call.GetWithdrawalIds()[0]
	callId := call.RequestId

	id := uuid.Must(uuid.NewV4()).String()
	var extra []byte
	extra = append(extra, uuid.Must(uuid.FromString(tid)).Bytes()...)
	extra = append(extra, uuid.Must(uuid.FromString(callId)).Bytes()...)
	for _, node := range nodes {
		out := testBuildObserverRequest(node, id, OperationTypeConfirmWithdrawal, extra)
		testStep(ctx, require, node, out)
		call, err := node.store.ReadSystemCallByRequestId(ctx, callId, common.RequestStateInitial)
		require.Nil(err)
		require.Equal("", call.WithdrawalIds)
		require.True(call.WithdrawedAt.Valid)
	}
}

func testUserRequestSystemCall(ctx context.Context, require *require.Assertions, nodes []*Node, mds []*mtg.SQLite3Store, user *store.User) *store.SystemCall {
	conf := nodes[0].conf

	sequence += 10
	_, err := testWriteOutputForNodes(ctx, mds, conf.AppId, common.SafeLitecoinChainId, "a8eed784060b200ea7f417309b12a33ced8344c24f5cdbe0237b7fc06125f459", "", sequence, decimal.NewFromInt(1000000))
	require.Nil(err)
	sequence += 10
	_, err = testWriteOutputForNodes(ctx, mds, conf.AppId, common.SafeSolanaChainId, "01c43005fd06e0b8f06a0af04faf7530331603e352a11032afd0fd9dbd84e8ee", "", sequence, decimal.NewFromInt(5000000))
	require.Nil(err)

	var c *store.SystemCall
	id := uuid.Must(uuid.NewV4()).String()
	hash := "d3b2db9339aee4acb39d0809fc164eb7091621400a9a3d64e338e6ffd035d32f"
	extra := user.IdBytes()
	extra = append(extra, common.DecodeHexOrPanic("02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000810cdc56c8d087a301b21144b2ab5e1286b50a5d941ee02f62488db0308b943d2d64375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca85002953f9517566994f5066c9478a5e6d0466906e7d844b2d971b2e4f86ff72561c6d6405387e0deff4ac3250e4e4d1986f1bc5e805edd8ca4c48b73b92441afdc070b84fed2e0ca7ecb2a18e32bf10885151641616b3fe4447557683ee699247e1f9cbad4af79952644bd80881b3934b3e278ad2f4eeea3614e1c428350d905eac4ecf6994777d4d13d8bd64679ac9e173a29ea40653734b52eee914ddc43c820f424071d460ef6501203e6656563c4add1638164d5eba1dee13e9085fb60036f98f10000000000000000000000000000000000000000000000000000000000000000816e66630c3bb724dc59e49f6cc4306e603a6aacca06fa3e34e2b40ad5979d8da5d5ca9e04cf5db590b714ba2fe32cb159133fc1c192b72257fd07d39cb0401ec4db1d1f598d6a8197daf51b68d7fc0ef139c4dec5a496bac9679563bd3127db069b8857feab8184fb687f634618c035dac439dc1aeb3b5598a0f0000000000106a7d517192c568ee08a845f73d29788cf035c3145b21ab344d8062ea940000006a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a0000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90ff0530009fc7a19cf8d8d0257f1dc2d478f1368aa89f5e546c6e12d8a4015ec020803050d0004040000000a0d0109030c0b020406070f0f080e20e992d18ecf6840bcd564b7ff16977c720000000000000000b992766700000000")...)
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
		c = call
	}
	return c
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
		user1, err := node.store.ReadUserByMixAddress(ctx, mix.String())
		require.Nil(err)
		require.Equal(mix.String(), user1.MixAddress)
		require.Equal(start.String(), user1.UserId)
		require.Equal("4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295", user1.Public)
		require.Equal("DaJw3pa9rxr25AT1HnQnmPvwS4JbnwNvQbNLm8PJRhqV", user1.NonceAccount)
		count, err := node.store.CountSpareNonceAccounts(ctx)
		require.Nil(err)
		require.Equal(3, count)

		_, share, err := node.store.ReadKeyByFingerprint(ctx, hex.EncodeToString(common.Fingerprint(user1.Public)))
		require.Nil(err)
		public, _ := node.deriveByPath(share, start.FillBytes(make([]byte, 8)))
		require.Equal(user1.ChainAddress, solana.PublicKeyFromBytes(public).String())
		user = user1

		id = uuid.Must(uuid.NewV4())
		seed = id.Bytes()
		seed = append(seed, id.Bytes()...)
		seed = append(seed, id.Bytes()...)
		seed = append(seed, id.Bytes()...)
		mix = mc.NewAddressFromSeed(seed)
		out = testBuildUserRequest(node, id.String(), "", OperationTypeAddUser, []byte(mix.String()))
		testStep(ctx, require, node, out)
		user2, err := node.store.ReadUserByMixAddress(ctx, mix.String())
		require.Nil(err)
		require.Equal(mix.String(), user2.MixAddress)
		require.Equal(big.NewInt(0).Add(start, big.NewInt(1)).String(), user2.UserId)
		require.Equal("4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295", user2.Public)
		require.NotEqual("", user1.NonceAccount)
		count, err = node.store.CountSpareNonceAccounts(ctx)
		require.Nil(err)
		require.Equal(2, count)
	}
	return user
}

func testObserverRequestCreateNonceAccount(ctx context.Context, require *require.Assertions, nodes []*Node) {
	as := [][2]string{
		{"DaJw3pa9rxr25AT1HnQnmPvwS4JbnwNvQbNLm8PJRhqV", "25DfFJbUsDMR7rYpieHhK7diWB1EuWkv5nB3F6CzNFTR"},
		testGenerateRandNonceAccount(require),
		{"7ipVMFwwgbvyum7yniEHrmxtbcpq6yVEY8iybr7vwsqC", "8uL2Fwc3WNnM7pYkXjn1sxHXGTBmWrB7HpNAtKuuLbEG"},
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

func testObserverSetPriceParams(ctx context.Context, require *require.Assertions, nodes []*Node) {
	for _, node := range nodes {
		params, err := node.store.ReadLatestOperationParams(ctx, time.Now().UTC())
		require.Nil(err)
		require.Nil(params)

		amount := decimal.RequireFromString(node.conf.OperationPriceAmount)
		logger.Printf("node.sendPriceInfo(%s, %s)", node.conf.OperationPriceAssetId, amount)
		amount = amount.Mul(decimal.New(1, 8))
		if amount.Sign() <= 0 || !amount.IsInteger() || !amount.BigInt().IsInt64() {
			panic(node.conf.OperationPriceAmount)
		}
		id := common.UniqueId("OperationTypeSetOperationParams", node.conf.OperationPriceAssetId)
		id = common.UniqueId(id, amount.String())
		extra := uuid.Must(uuid.FromString(node.conf.OperationPriceAssetId)).Bytes()
		extra = binary.BigEndian.AppendUint64(extra, uint64(amount.IntPart()))

		out := testBuildObserverRequest(node, id, OperationTypeSetOperationParams, extra)
		testStep(ctx, require, node, out)

		params, err = node.store.ReadLatestOperationParams(ctx, time.Now().UTC())
		require.Nil(err)
		require.NotNil(params)
		require.Equal(node.conf.OperationPriceAssetId, params.OperationPriceAsset)
		require.Equal(node.conf.OperationPriceAmount, params.OperationPriceAmount.String())
	}
}

func testObserverRequestGenerateKey(ctx context.Context, require *require.Assertions, nodes []*Node) {
	node := nodes[0]
	extra := []byte{0}
	id := uuid.Must(uuid.NewV4()).String()
	var sessionId string
	for _, node := range nodes {
		out := testBuildObserverRequest(node, id, OperationTypeKeygenInput, extra)
		sessionId = out.OutputId
		testStep(ctx, require, node, out)
		sessions, err := node.store.ListPreparedSessions(ctx, 500)
		require.Nil(err)
		require.Len(sessions, 1)
	}

	members := node.GetMembers()
	threshold := node.conf.MTG.Genesis.Threshold
	sessionId = common.UniqueId(sessionId, fmt.Sprintf("OperationTypeKeygenInput:%d", 0))
	sessionId = common.UniqueId(sessionId, fmt.Sprintf("MTG:%v:%d", members, threshold))
	for _, node := range nodes {
		testWaitOperation(ctx, node, sessionId)
	}
	time.Sleep(5 * time.Second)
	for _, node := range nodes {
		sessions, err := node.store.ListPreparedSessions(ctx, 500)
		require.Nil(err)
		require.Len(sessions, 0)
		sessions, err = node.store.ListPendingSessions(ctx, 500)
		require.Nil(err)
		require.Len(sessions, 0)
		count, err := node.store.CountKeys(ctx)
		require.Nil(err)
		require.Equal(1, count)
	}

	testFROSTPrepareKeys(ctx, require, nodes, testFROSTKeys1, "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b")
	count, err := node.store.CountKeys(ctx)
	require.Nil(err)
	require.Equal(2, count)
	key, err := node.store.ReadLatestKey(ctx)
	require.Nil(err)
	require.Equal("fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b", key)
	testFROSTPrepareKeys(ctx, require, nodes, testFROSTKeys2, "4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295")
	count, err = node.store.CountKeys(ctx)
	require.Nil(err)
	require.Equal(3, count)
	key, err = node.store.ReadLatestKey(ctx)
	require.Nil(err)
	require.Equal("4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295", key)
}

func testBuildUserRequest(node *Node, id, hash string, action byte, extra []byte) *mtg.Action {
	sequence += 10
	if hash == "" {
		hash = crypto.Sha256Hash([]byte(id)).String()
	}

	memo := []byte{action}
	memo = append(memo, extra...)
	memoStr := testEncodeMixinExtra(node.conf.AppId, memo)
	memoStr = hex.EncodeToString([]byte(memoStr))
	timestamp := time.Now().UTC()
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
	memo := []byte{action}
	memo = append(memo, extra...)
	memoStr := mtg.EncodeMixinExtraBase64(node.conf.AppId, memo)
	memoStr = hex.EncodeToString([]byte(memoStr))
	timestamp := time.Now().UTC()
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
	timestamp := time.Now().UTC()
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
	conf.Computer.SolanaDepositEntry = "4jGVQSJrCfgLNSvTfwTLejm88bUXppqwvBzFZADtsY2F"
	conf.Computer.MpcKeyNumber = 2

	if rpc := os.Getenv("SOLANARPC"); rpc != "" {
		conf.Computer.SolanaRPC = rpc
	}

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
		SequencerCreatedAt: time.Now().UTC(),
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
