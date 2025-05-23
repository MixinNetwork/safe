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

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gagliardetto/solana-go"
	"github.com/gofrs/uuid/v5"
	"github.com/pelletier/go-toml"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

var sequence uint64 = 5000000

func TestComputer(t *testing.T) {
	require := require.New(t)
	ctx, nodes, mds := testPrepare(require)

	testObserverRequestGenerateKey(ctx, require, nodes)
	testObserverRequestCreateNonceAccount(ctx, require, nodes)
	testObserverSetPriceParams(ctx, require, nodes)
	testObserverUpdateNetworInfo(ctx, require, nodes)
	testObserverRequestDeployAsset(ctx, require, nodes)

	user := testUserRequestAddUsers(ctx, require, nodes)
	call, sub := testUserRequestSystemCall(ctx, require, nodes, mds, user)
	testConfirmWithdrawal(ctx, require, nodes, call, sub)
	postprocess := testObserverConfirmMainCall(ctx, require, nodes, call)
	testObserverConfirmPostProcessCall(ctx, require, nodes, postprocess)

	node := nodes[0]
	err := node.store.WriteFailedCallIfNotExist(ctx, call, "test-error")
	require.Nil(err)
	reason, err := node.store.ReadFailReason(ctx, call.RequestId)
	require.Nil(err)
	require.Equal("test-error", reason)
}

func testObserverConfirmPostProcessCall(ctx context.Context, require *require.Assertions, nodes []*Node, sub *store.SystemCall) {
	node := nodes[0]
	err := node.store.UpdateNonceAccount(ctx, sub.NonceAccount, "6c8hGTPpTd4RMbYyM3wQgnwxZbajKhovhfDgns6bvmrX", sub.RequestId)
	require.Nil(err)
	nonce, err := node.store.ReadNonceAccount(ctx, sub.NonceAccount)
	require.Nil(err)
	require.Equal("6c8hGTPpTd4RMbYyM3wQgnwxZbajKhovhfDgns6bvmrX", nonce.Hash)
	require.False(nonce.CallId.Valid)
	require.Equal(sub.RequestId, nonce.UpdatedBy.String)

	id := uuid.Must(uuid.NewV4()).String()
	signature := solana.MustSignatureFromBase58("5s3UBMymdgDHwYvuaRdq9SLq94wj5xAgYEsDDB7TQwwuLy1TTYcSf6rF4f2fDfF7PnA9U75run6r1pKm9K1nusCR")
	extra := []byte{FlagConfirmCallSuccess, 1}
	extra = append(extra, signature[:]...)
	for _, node := range nodes {
		out := testBuildObserverRequest(node, id, OperationTypeConfirmCall, extra)
		testStep(ctx, require, node, out)

		sub, err := node.store.ReadSystemCallByRequestId(ctx, sub.RequestId, common.RequestStateDone)
		require.Nil(err)
		require.NotNil(sub)
		call, err := node.store.ReadSystemCallByRequestId(ctx, sub.Superior, common.RequestStateDone)
		require.Nil(err)
		require.NotNil(call)

		ar, _, err := node.store.ReadActionResult(ctx, id, id)
		require.Nil(err)
		require.Len(ar.Transactions, 1)
		require.Equal(common.SafeLitecoinChainId, ar.Transactions[0].AssetId)
	}
}

func testObserverConfirmMainCall(ctx context.Context, require *require.Assertions, nodes []*Node, call *store.SystemCall) *store.SystemCall {
	node := nodes[0]
	err := node.store.UpdateNonceAccount(ctx, call.NonceAccount, "E9esweXgoVfahhRvpWR4kefZXR54qd82ZGhVTbzQtCoX", call.RequestId)
	require.Nil(err)
	nonce, err := node.store.ReadNonceAccount(ctx, call.NonceAccount)
	require.Nil(err)
	require.Equal("E9esweXgoVfahhRvpWR4kefZXR54qd82ZGhVTbzQtCoX", nonce.Hash)
	require.Equal(call.RequestId, nonce.UpdatedBy.String)
	require.False(nonce.CallId.Valid)
	require.False(nonce.Mix.Valid)

	cid := common.UniqueId(call.RequestId, "post-process")
	err = node.store.OccupyNonceAccountByCall(ctx, nonce.Address, cid)
	require.Nil(err)
	stx := node.CreatePostProcessTransaction(ctx, call, nonce, nil, nil)
	require.NotNil(stx)
	raw, err := stx.MarshalBinary()
	require.Nil(err)

	id := uuid.Must(uuid.NewV4()).String()
	signatures := []solana.Signature{
		solana.MustSignatureFromBase58("2tPHv7kbUeHRWHgVKKddQqXnjDhuX84kTyCvRy1BmCM4m4Fkq4vJmNAz8A7fXqckrSNRTAKuPmAPWnzr5T7eCChb"),
		solana.MustSignatureFromBase58("39XBTQ7v6874uQb3vpF4zLe2asgNXjoBgQDkNiWya9ZW7UuG6DgY7kP4DFTRaGUo48NZF4qiZFGs1BuWJyCzRLtW"),
	}
	extra := []byte{FlagConfirmCallSuccess}
	extra = append(extra, byte(len(signatures)))
	for _, sig := range signatures {
		extra = append(extra, sig[:]...)
	}
	extra = attachSystemCall(extra, cid, raw)

	var postprocess *store.SystemCall
	out := testBuildObserverRequest(node, id, OperationTypeConfirmCall, extra)
	for _, node := range nodes {
		go testStep(ctx, require, node, out)
	}
	testObserverRequestSignSystemCall(ctx, require, nodes, cid)
	for _, node := range nodes {
		main, err := node.store.ReadSystemCallByRequestId(ctx, call.RequestId, common.RequestStateDone)
		require.Nil(err)
		require.NotNil(main)
		sub, err := node.store.ReadSystemCallByRequestId(ctx, cid, common.RequestStatePending)
		require.Nil(err)
		require.NotNil(sub)
		require.Equal(main.RequestId, sub.Superior)
		require.Equal(store.CallTypePostProcess, sub.Type)
		require.Len(sub.GetWithdrawalIds(), 0)
		require.True(sub.WithdrawnAt.Valid)
		require.True(sub.Signature.Valid)
		require.True(sub.RequestSignerAt.Valid)
		postprocess = sub

		os, err := node.store.ListUserOutputsByHashAndState(ctx, "a8eed784060b200ea7f417309b12a33ced8344c24f5cdbe0237b7fc06125f459", common.RequestStateDone)
		require.Nil(err)
		require.Len(os, 1)
		os, err = node.store.ListUserOutputsByHashAndState(ctx, "01c43005fd06e0b8f06a0af04faf7530331603e352a11032afd0fd9dbd84e8ee", common.RequestStateDone)
		require.Nil(err)
		require.Len(os, 1)
	}
	return postprocess
}

func testConfirmWithdrawal(ctx context.Context, require *require.Assertions, nodes []*Node, call, sub *store.SystemCall) {
	tid := call.GetWithdrawalIds()[0]
	callId := call.RequestId

	id := uuid.Must(uuid.NewV4()).String()
	sig := solana.MustSignatureFromBase58("jmHyRpKEuc1PgDjDaqaQqo9GpSM3pp9PhLgwzqpfa2uUbtRYJmbKtWp4onfNFsbk47paBjxz1d6s9n56Y8Na9Hp")
	var extra []byte
	extra = append(extra, uuid.Must(uuid.FromString(tid)).Bytes()...)
	extra = append(extra, uuid.Must(uuid.FromString(callId)).Bytes()...)
	extra = append(extra, sig[:]...)
	for _, node := range nodes {
		out := testBuildObserverRequest(node, id, OperationTypeConfirmWithdrawal, extra)
		testStep(ctx, require, node, out)
		call, err := node.store.ReadSystemCallByRequestId(ctx, callId, common.RequestStatePending)
		require.Nil(err)
		require.Equal("", call.WithdrawalTraces.String)
		require.True(call.WithdrawnAt.Valid)
		call, err = node.store.ReadSystemCallByRequestId(ctx, sub.RequestId, common.RequestStatePending)
		require.Nil(err)
		require.NotNil(call)
	}
}

func testUserRequestSystemCall(ctx context.Context, require *require.Assertions, nodes []*Node, mds []*mtg.SQLite3Store, user *store.User) (*store.SystemCall, *store.SystemCall) {
	node := nodes[0]
	conf := node.conf
	nonce, err := node.store.ReadNonceAccount(ctx, "DaJw3pa9rxr25AT1HnQnmPvwS4JbnwNvQbNLm8PJRhqV")
	require.Nil(err)
	require.False(nonce.Mix.Valid)
	require.False(nonce.CallId.Valid)
	err = node.store.LockNonceAccountWithMix(ctx, nonce.Address, user.MixAddress)
	require.Nil(err)

	sequence += 10
	h1, _ := crypto.HashFromString("a8eed784060b200ea7f417309b12a33ced8344c24f5cdbe0237b7fc06125f459")
	_, err = testWriteOutputForNodes(ctx, mds, conf.AppId, common.SafeLitecoinChainId, h1.String(), "", sequence, decimal.RequireFromString("0.01"))
	require.Nil(err)
	oid1, err := uuid.NewV4()
	require.Nil(err)
	extra := user.IdBytes()
	out1 := testBuildUserRequest(node, oid1.String(), h1.String(), "0.01", common.SafeLitecoinChainId, OperationTypeUserDeposit, extra, nil, nil)
	sequence += 10
	h2, _ := crypto.HashFromString("01c43005fd06e0b8f06a0af04faf7530331603e352a11032afd0fd9dbd84e8ee")
	_, err = testWriteOutputForNodes(ctx, mds, conf.AppId, common.SafeSolanaChainId, h2.String(), "", sequence, decimal.RequireFromString("0.005"))
	require.Nil(err)
	oid2, err := uuid.NewV4()
	require.Nil(err)
	out2 := testBuildUserRequest(node, oid2.String(), h2.String(), "0.005", common.SafeSolanaChainId, OperationTypeUserDeposit, extra, nil, nil)
	for _, node := range nodes {
		err = node.store.WriteProperty(ctx, h1.String(), "7777000546dbd75ed416c82652554a2fd257df3adb5d8c68726db6631bf1300e7aa36f4100013db24d1350f18126b0f93309913d237fcb870f63fb42cafb3a7d0202aca77bd200000000000000000001000000030f4240000103551f38d1ae2002e06892803b57c838012123911681dc567564e63042c3377690b6636bc74fa394d9122c6af4415d4d151c9671eb82d43c096ea01635bc177f0003fffe01000000000000007854554638593251794e5745334d6a5174593249354d7930304d324d784c546c6d4e6a6774595746695a6d4e6a4d7a4d344f446334664656515245465552563950556b5246556e786d4e446730593255794f53307a596d597a4c5451354d5755744f44677a5a6930334e6d4935596a68694e6a526a4d32453d00010001000052bf7fb6ce4e61527b1cec54d8b705b66c24876d7f53672f9f398c30c20e57136fe4853a40ae7b02a81f038055a09a1e3b0034c62a06960934c38db41701c60b")
		require.Nil(err)
		err = node.store.WriteProperty(ctx, h2.String(), "77770005481360491383ebd4f0f97543f3440313b48b8fd06dcfa5a0c2cabe4252d3a8eb000130ae0a78947f751fc7be11674c6bd93492069b5cec475c22a4afa382ed543f4c000000000000000000020000000307a12000029a0f3710baf7a8d1695b7abdabc360a79e05a389767073defac81cf9822d75e232d53fe83b77deebbe4da8eddbb88c8e3eae4ebfcd7ae5f17670445ebd84122bfb02ce99af492d1980209ed90919379d2cd2e64836383f60fb3ed10a58043b180003fffe020000000000026b4700012c1d4c257f92cc8dd39e2feb70c14708b593c122cb77714bb5fd5bd55753f96e5fed9e5daeb367bcacbc3e68bb3c147b443fc6e3a40018dc1677c538abf55f7a0003fffe010000000000000000000100010000b4cf2a72adf8014550860fdc2e078163925f6b6baef6086e4b56d7e9f1beccffac0fd298131419f9aa3596e2efd466e35d06fc764491f5c31ac2e464ffaab90b")
		require.Nil(err)

		testStep(ctx, require, node, out1)
		testStep(ctx, require, node, out2)

		os, err := node.store.ListUserOutputsByHashAndState(ctx, h1.String(), common.RequestStateInitial)
		require.Nil(err)
		require.Len(os, 1)
		os, err = node.store.ListUserOutputsByHashAndState(ctx, h2.String(), common.RequestStateInitial)
		require.Nil(err)
		require.Len(os, 1)
	}

	solAmount := decimal.RequireFromString("0.23456789")
	fee, err := node.store.ReadLatestFeeInfo(ctx)
	require.Nil(err)
	ratio := decimal.RequireFromString(fee.Ratio)
	xinAmount := solAmount.Div(ratio).RoundCeil(8).String()
	require.Equal("0.28271639", xinAmount)
	xinFee := decimal.RequireFromString(xinAmount)

	id := uuid.Must(uuid.NewV4()).String()
	refs := testStorageSystemCall(ctx, nodes, common.DecodeHexOrPanic("02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000810cdc56c8d087a301b21144b2ab5e1286b50a5d941ee02f62488db0308b943d2d64375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca85002953f9517566994f5066c9478a5e6d0466906e7d844b2d971b2e4f86ff72561c6d6405387e0deff4ac3250e4e4d1986f1bc5e805edd8ca4c48b73b92441afdc070b84fed2e0ca7ecb2a18e32bf10885151641616b3fe4447557683ee699247e1f9cbad4af79952644bd80881b3934b3e278ad2f4eeea3614e1c428350d905eac4ecf6994777d4d13d8bd64679ac9e173a29ea40653734b52eee914ddc43c820f424071d460ef6501203e6656563c4add1638164d5eba1dee13e9085fb60036f98f10000000000000000000000000000000000000000000000000000000000000000816e66630c3bb724dc59e49f6cc4306e603a6aacca06fa3e34e2b40ad5979d8da5d5ca9e04cf5db590b714ba2fe32cb159133fc1c192b72257fd07d39cb0401ec4db1d1f598d6a8197daf51b68d7fc0ef139c4dec5a496bac9679563bd3127db069b8857feab8184fb687f634618c035dac439dc1aeb3b5598a0f0000000000106a7d517192c568ee08a845f73d29788cf035c3145b21ab344d8062ea940000006a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a0000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90ff0530009fc7a19cf8d8d0257f1dc2d478f1368aa89f5e546c6e12d8a4015ec020803050d0004040000000a0d0109030c0b020406070f0f080e20e992d18ecf6840bcd564b7ff16977c720000000000000000b992766700000000"))
	refs = append(refs, []crypto.Hash{h1, h2}...)

	hash := "d3b2db9339aee4acb39d0809fc164eb7091621400a9a3d64e338e6ffd035d32f"
	extra = user.IdBytes()
	extra = append(extra, uuid.Must(uuid.FromString(id)).Bytes()...)
	extra = append(extra, FlagWithPostProcess)
	extra = append(extra, uuid.Must(uuid.FromString(fee.Id)).Bytes()...)
	out := testBuildUserRequest(node, id, hash, "0.001", mtg.StorageAssetId, OperationTypeSystemCall, extra, refs, &xinFee)
	for _, node := range nodes {
		testStep(ctx, require, node, out)
		call, err := node.store.ReadSystemCallByRequestId(ctx, id, common.RequestStateInitial)
		require.Nil(err)
		require.Equal(id, call.RequestId)
		require.Equal(out.OutputId, call.Superior)
		require.Equal(store.CallTypeMain, call.Type)
		require.Equal(hex.EncodeToString(user.FingerprintWithPath()), call.Public)
		require.False(call.WithdrawnAt.Valid)
		require.False(call.Signature.Valid)
		require.True(call.RequestSignerAt.Valid)
		os, _, err := node.GetSystemCallReferenceOutputs(ctx, call.RequestHash, common.RequestStatePending)
		require.Nil(err)
		require.Len(os, 2)
	}

	cs, err := node.store.ListUnconfirmedSystemCalls(ctx)
	require.Nil(err)
	require.Len(cs, 1)
	c := cs[0]
	nonce, err = node.store.ReadNonceAccount(ctx, c.NonceAccount)
	require.Nil(err)
	require.True(nonce.LockedByUserOnly())
	user, err = node.store.ReadUser(ctx, c.UserIdFromPublicPath())
	require.Nil(err)
	require.Equal(user.MixAddress, nonce.Mix.String)
	err = node.store.OccupyNonceAccountByCall(ctx, c.NonceAccount, c.RequestId)
	require.Nil(err)

	nonce, err = node.store.ReadSpareNonceAccount(ctx)
	require.Nil(err)
	require.Equal("7ipVMFwwgbvyum7yniEHrmxtbcpq6yVEY8iybr7vwsqC", nonce.Address)
	require.Equal("8uL2Fwc3WNnM7pYkXjn1sxHXGTBmWrB7HpNAtKuuLbEG", nonce.Hash)
	extraFee, err := node.getSystemCallFeeFromXIN(ctx, c, false)
	require.Nil(err)
	feeActual := decimal.RequireFromString(extraFee.Amount)
	require.True(feeActual.Cmp(solAmount) >= 0)
	stx, err := node.CreatePrepareTransaction(ctx, c, nonce, extraFee)
	require.Nil(err)
	require.NotNil(stx)
	raw, err := stx.MarshalBinary()
	require.Nil(err)
	cid := common.UniqueId(c.RequestId, "prepare")

	id = uuid.Must(uuid.NewV4()).String()
	extra = []byte{ConfirmFlagNonceAvailable}
	extra = append(extra, uuid.Must(uuid.FromString(c.RequestId)).Bytes()...)
	extra = attachSystemCall(extra, cid, raw)

	out = testBuildObserverRequest(node, id, OperationTypeConfirmNonce, extra)
	var sub *store.SystemCall
	for _, node := range nodes {
		go testStep(ctx, require, node, out)
	}
	time.Sleep(10 * time.Second)
	for _, node := range nodes {
		call, err := node.store.ReadSystemCallByRequestId(ctx, c.RequestId, common.RequestStateInitial)
		require.Nil(err)
		require.Len(call.GetWithdrawalIds(), 1)
		require.False(call.WithdrawnAt.Valid)
		c = call
		call, err = node.store.ReadSystemCallByRequestId(ctx, cid, common.RequestStateInitial)
		require.Nil(err)
		require.True(call.WithdrawalTraces.Valid)
		require.True(call.WithdrawnAt.Valid)
		sub = call
	}
	testObserverRequestSignSystemCall(ctx, require, nodes, cid)
	testObserverRequestSignSystemCall(ctx, require, nodes, c.RequestId)
	return c, sub
}

func testUserRequestAddUsers(ctx context.Context, require *require.Assertions, nodes []*Node) *store.User {
	start := big.NewInt(0).Add(store.StartUserId, big.NewInt(1))
	var user *store.User
	var as []string
	id := uuid.Must(uuid.NewV4()).String()
	for _, node := range nodes {
		uid := common.UniqueId(id, "user1")
		mix := bot.NewUUIDMixAddress([]string{uid}, 1)
		out := testBuildUserRequest(node, id, "", "0.001", mtg.StorageAssetId, OperationTypeAddUser, []byte(mix.String()), nil, nil)
		testStep(ctx, require, node, out)
		user1, err := node.store.ReadUserByMixAddress(ctx, mix.String())
		require.Nil(err)
		require.Equal(mix.String(), user1.MixAddress)
		require.Equal(start.String(), user1.UserId)
		require.Equal("4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295", user1.Public)

		_, share, err := node.store.ReadKeyByFingerprint(ctx, hex.EncodeToString(common.Fingerprint(user1.Public)))
		require.Nil(err)
		public, _ := node.deriveByPath(share, user1.IdBytes())
		require.Equal(solana.PublicKeyFromBytes(public).String(), user1.ChainAddress)
		as = append(as, user1.ChainAddress)
		user = user1

		id2 := common.UniqueId(id, "second")
		uid = common.UniqueId(id, "user2")
		mix = bot.NewUUIDMixAddress([]string{uid}, 1)
		out = testBuildUserRequest(node, id2, "", "0.001", mtg.StorageAssetId, OperationTypeAddUser, []byte(mix.String()), nil, nil)
		testStep(ctx, require, node, out)
		user2, err := node.store.ReadUserByMixAddress(ctx, mix.String())
		require.Nil(err)
		require.Equal(mix.String(), user2.MixAddress)
		require.Equal(big.NewInt(0).Add(start, big.NewInt(1)).String(), user2.UserId)
		require.Equal("4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295", user2.Public)
		as = append(as, user2.ChainAddress)

		us, err := node.store.ListNewUsersAfter(ctx, time.Time{})
		require.Nil(err)
		require.Len(us, 2)
	}

	c, err := nodes[0].store.CheckInternalAccounts(ctx, []string{"1", "2"})
	require.Nil(err)
	require.Equal(0, c)
	c, err = nodes[0].store.CheckInternalAccounts(ctx, as)
	require.Nil(err)
	require.Equal(2, c)
	as = append(as, "1")
	c, err = nodes[0].store.CheckInternalAccounts(ctx, as)
	require.Nil(err)
	require.Equal(2, c)
	return user
}

func testObserverRequestCreateNonceAccount(ctx context.Context, require *require.Assertions, nodes []*Node) {
	as := [][2]string{
		{"DaJw3pa9rxr25AT1HnQnmPvwS4JbnwNvQbNLm8PJRhqV", "25DfFJbUsDMR7rYpieHhK7diWB1EuWkv5nB3F6CzNFTR"},
		{"7ipVMFwwgbvyum7yniEHrmxtbcpq6yVEY8iybr7vwsqC", "8uL2Fwc3WNnM7pYkXjn1sxHXGTBmWrB7HpNAtKuuLbEG"},
		{"ByaBrgG365HHJfMiybAg3sJfFuyj6oEou2cA6Cs4DfT6", "GPr2BFAJEdYeevsehok3UABvAHS6E6CXi36HNYeEbggo"},
		testGenerateRandNonceAccount(require),
	}
	node := nodes[0]

	for _, nonce := range as {
		err := node.store.WriteNonceAccount(ctx, nonce[0], nonce[1])
		require.Nil(err)
	}
	count, err := node.store.CountNonceAccounts(ctx)
	require.Nil(err)
	require.Equal(4, count)
}

func testObserverUpdateNetworInfo(ctx context.Context, require *require.Assertions, nodes []*Node) {
	for _, node := range nodes {
		fee, err := node.store.ReadLatestFeeInfo(ctx)
		require.Nil(err)
		require.Nil(fee)

		xinPrice := decimal.RequireFromString("105.23")
		solPrice := decimal.RequireFromString("126.83")
		ratio := xinPrice.Div(solPrice).String()
		require.Equal("0.8296932902310179", ratio)

		id := common.UniqueId("OperationTypeUpdateFeeInfo", string(node.id))
		id = common.UniqueId(id, ratio)
		extra := []byte(ratio)

		out := testBuildObserverRequest(node, id, OperationTypeUpdateFeeInfo, extra)
		testStep(ctx, require, node, out)

		fee, err = node.store.ReadLatestFeeInfo(ctx)
		require.Nil(err)
		require.NotNil(fee)
		require.Equal(ratio, fee.Ratio)
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

func testObserverRequestDeployAsset(ctx context.Context, require *require.Assertions, nodes []*Node) {
	node := nodes[0]

	nonce, err := node.store.ReadNonceAccount(ctx, "ByaBrgG365HHJfMiybAg3sJfFuyj6oEou2cA6Cs4DfT6")
	require.Nil(err)
	require.False(nonce.CallId.Valid)
	require.False(nonce.Mix.Valid)
	err = node.store.WriteExternalAssets(ctx, []*store.ExternalAsset{
		{
			AssetId:   common.SafeLitecoinChainId,
			CreatedAt: time.Now().UTC(),
		},
	})
	require.Nil(err)
	cid, stx, assets, err := node.CreateMintsTransaction(ctx, []string{common.SafeLitecoinChainId})
	require.Nil(err)
	raw, err := stx.MarshalBinary()
	require.Nil(err)

	var extra []byte
	extra = append(extra, byte(len(assets)))
	for _, asset := range assets {
		extra = append(extra, uuid.Must(uuid.FromString(asset.AssetId)).Bytes()...)
		extra = append(extra, solana.MustPublicKeyFromBase58(asset.Address).Bytes()...)
	}
	extra = attachSystemCall(extra, cid, raw)

	id := uuid.Must(uuid.NewV4()).String()
	out := testBuildObserverRequest(node, id, OperationTypeDeployExternalAssets, extra)
	for _, node := range nodes {
		go testStep(ctx, require, node, out)
	}
	testObserverRequestSignSystemCall(ctx, require, nodes, cid)

	id = common.UniqueId(id, "confirm")
	sig := solana.MustSignatureFromBase58("MBsH9LRbrx4u3kMkFkGuDyxjj3Pio55Puwv66dtR2M3CDfaR7Ef7VEKHDGM7GhB3fE1Jzc7k3zEZ6hvJ399UBNi")
	extra = []byte{FlagConfirmCallSuccess, 1}
	extra = append(extra, sig[:]...)
	for _, node := range nodes {
		call, err := node.store.ReadSystemCallByRequestId(ctx, cid, common.RequestStatePending)
		require.Nil(err)
		require.NotNil(call)
		asset, err := node.store.ReadDeployedAsset(ctx, common.SafeLitecoinChainId, common.RequestStateInitial)
		require.Nil(err)
		require.Equal("EFShFtXaMF1n1f6k3oYRd81tufEXzUuxYM6vkKrChVs8", asset.Address)
		require.Equal(int64(8), asset.Decimals)
		require.Equal(int64(common.RequestStateInitial), asset.State)
		out := testBuildObserverRequest(node, id, OperationTypeConfirmCall, extra)
		testStep(ctx, require, node, out)
		asset, err = node.store.ReadDeployedAsset(ctx, common.SafeLitecoinChainId, common.RequestStateDone)
		require.Nil(err)
		require.Equal(int64(common.RequestStateDone), asset.State)
	}

	call, err := node.store.ReadSystemCallByRequestId(ctx, cid, 0)
	require.Nil(err)
	err = node.store.ReleaseLockedNonceAccount(ctx, call.NonceAccount)
	require.Nil(err)
}

func testObserverRequestGenerateKey(ctx context.Context, require *require.Assertions, nodes []*Node) {
	node := nodes[0]
	count, err := node.store.CountKeys(ctx)
	require.Nil(err)
	require.Equal(0, count)
	testFROSTPrepareKeys(ctx, require, nodes, testFROSTKeys1, "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b")

	extra := []byte{1}
	id := uuid.Must(uuid.NewV4()).String()
	var sessionId string
	for _, node := range nodes {
		count, err = node.store.CountKeys(ctx)
		require.Nil(err)
		require.Equal(1, count)
		key, err := node.store.ReadLatestPublicKey(ctx)
		require.Nil(err)
		require.Equal("fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b", key)

		out := testBuildObserverRequest(node, id, OperationTypeKeygenInput, extra)
		sessionId = out.OutputId
		testStep(ctx, require, node, out)
		sessions, err := node.store.ListPreparedSessions(ctx, 500)
		require.Nil(err)
		require.Len(sessions, 1)
	}

	members := node.GetMembers()
	threshold := node.conf.MTG.Genesis.Threshold
	sessionId = common.UniqueId(sessionId, fmt.Sprintf("OperationTypeKeygenInput:%d", 1))
	sessionId = common.UniqueId(sessionId, fmt.Sprintf("MTG:%v:%d", members, threshold))
	for _, node := range nodes {
		testWaitOperation(ctx, node, sessionId)
	}
	time.Sleep(15 * time.Second)
	for _, node := range nodes {
		sessions, err := node.store.ListPreparedSessions(ctx, 500)
		require.Nil(err)
		require.Len(sessions, 0)
		sessions, err = node.store.ListPendingSessions(ctx, 500)
		require.Nil(err)
		require.Len(sessions, 0)
		count, err := node.store.CountKeys(ctx)
		require.Nil(err)
		require.Equal(2, count)
	}

	testFROSTPrepareKeys(ctx, require, nodes, testFROSTKeys2, "4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295")
	count, err = node.store.CountKeys(ctx)
	require.Nil(err)
	require.Equal(3, count)
	key, err := node.store.ReadLatestPublicKey(ctx)
	require.Nil(err)
	require.Equal("4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295", key)
}

func testStorageSystemCall(ctx context.Context, nodes []*Node, extra []byte) []crypto.Hash {
	raw := base64.RawURLEncoding.EncodeToString(extra)
	ref := crypto.Sha256Hash(extra)
	refs := []crypto.Hash{ref}

	for _, node := range nodes {
		err := node.store.WriteProperty(ctx, ref.String(), raw)
		if err != nil {
			panic(err)
		}
	}
	return refs
}

func testObserverRequestSignSystemCall(ctx context.Context, require *require.Assertions, nodes []*Node, cid string) {
	for _, node := range nodes {
		testWaitOperation(ctx, node, cid)
	}
	for _, node := range nodes {
		call, err := node.store.ReadSystemCallByRequestId(ctx, cid, 0)
		require.Nil(err)
		require.True(call.Signature.Valid)
	}
}

func testBuildUserRequest(node *Node, id, hash, amt, asset string, action byte, extra []byte, references []crypto.Hash, fee *decimal.Decimal) *mtg.Action {
	sequence += 10
	if hash == "" {
		hash = crypto.Sha256Hash([]byte(id)).String()
	}

	memo := []byte{action}
	memo = append(memo, extra...)
	memoStr := testEncodeMixinExtra(node.conf.AppId, memo)
	memoStr = hex.EncodeToString([]byte(memoStr))
	timestamp := time.Now().UTC()

	amount := decimal.RequireFromString(amt)
	if fee != nil {
		amount = amount.Add(*fee)
	}

	writeOutputReferences(id, references)
	return &mtg.Action{
		UnifiedOutput: mtg.UnifiedOutput{
			OutputId:           id,
			TransactionHash:    hash,
			AppId:              node.conf.AppId,
			Senders:            []string{string(node.id)},
			AssetId:            asset,
			Extra:              memoStr,
			Amount:             amount,
			SequencerCreatedAt: timestamp,
			Sequence:           sequence,
		},
	}
}

func testBuildObserverRequest(node *Node, id string, action byte, extra []byte) *mtg.Action {
	sequence += 10
	memo := []byte{action}
	memo = append(memo, extra...)
	signed := node.signObserverExtra(memo)
	memoStr := mtg.EncodeMixinExtraBase64(node.conf.AppId, signed)
	memoStr = hex.EncodeToString([]byte(memoStr))
	timestamp := time.Now().UTC()

	return &mtg.Action{
		UnifiedOutput: mtg.UnifiedOutput{
			OutputId:           id,
			TransactionHash:    crypto.Sha256Hash([]byte(id)).String(),
			AppId:              node.conf.AppId,
			Senders:            []string{string(node.id)},
			AssetId:            bot.XINAssetId,
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
	req, err := node.store.TestReadPendingRequest(ctx)
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

func testPrepare(require *require.Assertions) (context.Context, []*Node, []*mtg.SQLite3Store) {
	logger.SetLevel(logger.INFO)
	ctx := context.Background()
	ctx = common.EnableTestEnvironment(ctx)

	nodes := make([]*Node, 4)
	mds := make([]*mtg.SQLite3Store, 4)
	for i := 0; i < 4; i++ {
		dir := fmt.Sprintf("safe-signer-test-%d", i)
		root, err := os.MkdirTemp("", dir)
		require.Nil(err)
		nodes[i], mds[i] = testBuildNode(ctx, require, root, i)
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

	return ctx, nodes, mds
}

func testBuildNode(ctx context.Context, require *require.Assertions, root string, i int) (*Node, *mtg.SQLite3Store) {
	f, _ := os.ReadFile("../config/example.toml")
	var conf struct {
		Computer *Configuration `toml:"computer"`
	}
	err := toml.Unmarshal(f, &conf)
	require.Nil(err)

	conf.Computer.StoreDir = root
	conf.Computer.MTG.App.AppId = conf.Computer.MTG.Genesis.Members[i]
	conf.Computer.MTG.GroupSize = 1
	conf.Computer.SolanaDepositEntry = "4jGVQSJrCfgLNSvTfwTLejm88bUXppqwvBzFZADtsY2F"
	conf.Computer.MPCKeyNumber = 3

	seed := crypto.Sha256Hash([]byte("computer-test"))
	key := crypto.NewKeyFromSeed(append(seed[:], seed[:]...))
	conf.Computer.MTG.App.SpendPrivateKey = key.String()
	conf.Computer.ObserverPublicKey = key.Public().String()

	if rpc := os.Getenv("SOLANARPC"); rpc != "" {
		conf.Computer.SolanaRPC = rpc
	}

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
		_, err := testWriteOutputForNodes(ctx, mds, conf.AppId, mtg.StorageAssetId, "", "", uint64(sequence), decimal.NewFromInt(1))
		require.Nil(err)
		sequence += uint64(i + 1)
	}
	for i := range 100 {
		_, err := testWriteOutputForNodes(ctx, mds, conf.AppId, common.SafeSolanaChainId, "", "", uint64(sequence), decimal.NewFromInt(1))
		require.Nil(err)
		sequence += uint64(i + 1)
	}
	for _, node := range nodes {
		os := node.group.ListOutputsForAsset(ctx, conf.AppId, conf.AssetId, start, sequence, mtg.SafeUtxoStateUnspent, 500)
		require.Len(os, 100)
		os = node.group.ListOutputsForAsset(ctx, conf.AppId, mtg.StorageAssetId, start, sequence, mtg.SafeUtxoStateUnspent, 500)
		require.Len(os, 100)
		os = node.group.ListOutputsForAsset(ctx, conf.AppId, common.SafeSolanaChainId, start, sequence, mtg.SafeUtxoStateUnspent, 500)
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
