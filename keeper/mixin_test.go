package keeper

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/mixin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/signer"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

const (
	testMixinKernelAddress             = "XINZrJcfd6QoKrR7Q31YY7gk2zvbU1qkAAZ4xBan4KQYeDq7sZ21g4WFsa2bXKoXSWy4sRvr8grSBRmXPxjDBHbF4jaik5om"
	testMixinKernelHolderPrivate       = "6761ad91d9784b92b14f6be83fdd364a0a722367bbbf8525a95d4153bf8e7008"
	testMixinKernelObserverPrivate     = "218a231184dc3be90183118b83f854df3057a53f7a9edb886a12d434ed8fcb06"
	testMixinKernelDummyHolderPrivate  = "1000c89522d07e0acf4bf65c1d07f662e7d6412c49d4881818817b5726d1a802"
	testMixinKernelBondAssetId         = "afd17288-1765-3d37-ba91-43bb73448ae0"
	testMixinKernelTransactionReceiver = "XINZrJcfd6QoKrR7Q31YY7gk2zvbU1qkAAZ4xBan4KQYeDq7sZ21g4WFsa2bXKoXSWy4sRvr8grSBRmXPxjDBHbF4jaik5om"
)

func TestMixinKeeper(t *testing.T) {
	require := require.New(t)
	ctx, node, mpc, signers := testMixinKernelPrepare(require)

	observer := testMixinKernelPublicKey(testMixinKernelObserverPrivate)
	bondId := testDeployBondContract(ctx, require, node, testMixinKernelAddress, SafeMixinKernelAssetId)
	require.Equal(testMixinKernelBondAssetId, bondId)
	node.ProcessOutput(ctx, &mtg.Output{AssetID: bondId, Amount: decimal.NewFromInt(1000000), CreatedAt: time.Now()})
	input := &mixin.Input{
		TransactionHash: "74e131b1224af9cb3d644eaf10ed6ee8e9af1dc73981bfc61f3e6cb8d4d4c7e2",
		Index:           0,
		Amount:          decimal.RequireFromString("0.000123"),
	}
	testMixinKernelObserverHolderDeposit(ctx, require, node, mpc, observer, input, 1)
	input = &mixin.Input{
		TransactionHash: "74e131b1224af9cb3d644eaf10ed6ee8e9af1dc73981bfc61f3e6cb8d4d4c7e2",
		Index:           1,
		Amount:          decimal.RequireFromString("0.006877"),
	}
	testMixinKernelObserverHolderDeposit(ctx, require, node, mpc, observer, input, 2)

	holder := testMixinKernelPublicKey(testMixinKernelHolderPrivate)
	outputs, err := node.store.ListAllMixinKernelUTXOsForHolderAndAsset(ctx, holder, SafeMixinKernelAssetId)
	require.Nil(err)
	require.Len(outputs, 2)
	pendings, err := node.store.ListPendingMixinKernelUTXOsForHolderAndAsset(ctx, holder, SafeMixinKernelAssetId)
	require.Nil(err)
	require.Len(pendings, 0)

	transactionHash := testMixinKernelProposeTransaction(ctx, require, node, mpc, bondId, "3e37ea1c-1455-400d-9642-f6bbcd8c744e", "c330608a509b84a6cc8063249145dbdd880885f8c8c1f6593400a37b399c5f62", "77770004a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc000274e131b1224af9cb3d644eaf10ed6ee8e9af1dc73981bfc61f3e6cb8d4d4c7e2000000000000000074e131b1224af9cb3d644eaf10ed6ee8e9af1dc73981bfc61f3e6cb8d4d4c7e20001000000000000000200000002300c000120253714361d28713900f1b6b09d4b38565fa041cbb4b20da8e8e3169ced26b1a11e825b186b695bc72cdbd312ca8b03457d4c592e33dfd66fa46d226dcfcc220003fffe010000000000030a7e54000162ddce376ba321f5766842f5953b6896992d8d515fb2061247972f6332a1c5b82ef07340f5fd41b9fc5f106bb0df32b651c2ccee1ba66ccb9fc165da60da696d0003fffe0100000000000000103e37ea1c1455400d9642f6bbcd8c744e0000")
	outputs, err = node.store.ListAllMixinKernelUTXOsForHolderAndAsset(ctx, holder, SafeMixinKernelAssetId)
	require.Nil(err)
	require.Len(outputs, 0)
	pendings, err = node.store.ListPendingMixinKernelUTXOsForHolderAndAsset(ctx, holder, SafeMixinKernelAssetId)
	require.Nil(err)
	require.Len(pendings, 2)
	testMixinKernelRevokeTransaction(ctx, require, node, transactionHash, false)
	outputs, err = node.store.ListAllMixinKernelUTXOsForHolderAndAsset(ctx, holder, SafeMixinKernelAssetId)
	require.Nil(err)
	require.Len(outputs, 2)
	pendings, err = node.store.ListPendingMixinKernelUTXOsForHolderAndAsset(ctx, holder, SafeMixinKernelAssetId)
	require.Nil(err)
	require.Len(pendings, 0)

	transactionHash = testMixinKernelProposeTransaction(ctx, require, node, mpc, bondId, "b0a22078-0a86-459d-93f4-a1aadbf2b9b7", "633a03e24ec62f28ff1e2769fc98a18dc8141c61db5ab7fdec240e546a384cdc", "77770004a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc000274e131b1224af9cb3d644eaf10ed6ee8e9af1dc73981bfc61f3e6cb8d4d4c7e2000000000000000074e131b1224af9cb3d644eaf10ed6ee8e9af1dc73981bfc61f3e6cb8d4d4c7e20001000000000000000200000002300c0001317c78dd1f1ff39ed14c0ba595536da85c04ffcfc4c349dcb18651c254be3f41369e617a18e7655e927e5f0f3805f5fd8d182888556311f626f441b02ac81a010003fffe010000000000030a7e5400011af4766dbf46790d9d87e0427421b0ce6d9720c8d8327f8c3390eadcb48ac8d196e7f0d15190e22a1c07ed9faa9ecfa54c88b4bc77539ab7afc977b6a541ed690003fffe010000000000000010b0a220780a86459d93f4a1aadbf2b9b70000")
	outputs, err = node.store.ListAllMixinKernelUTXOsForHolderAndAsset(ctx, holder, SafeMixinKernelAssetId)
	require.Nil(err)
	require.Len(outputs, 0)
	pendings, err = node.store.ListPendingMixinKernelUTXOsForHolderAndAsset(ctx, holder, SafeMixinKernelAssetId)
	require.Nil(err)
	require.Len(pendings, 2)
	testMixinKernelApproveTransaction(ctx, require, node, transactionHash, signers)
	outputs, err = node.store.ListAllMixinKernelUTXOsForHolderAndAsset(ctx, holder, SafeMixinKernelAssetId)
	require.Nil(err)
	require.Len(outputs, 0)
	pendings, err = node.store.ListPendingMixinKernelUTXOsForHolderAndAsset(ctx, holder, SafeMixinKernelAssetId)
	require.Nil(err)
	require.Len(pendings, 0)
	testSpareKeys(ctx, require, node, 0, 0, 0, common.CurveEdwards25519Mixin)
}

func testMixinKernelPrepare(require *require.Assertions) (context.Context, *Node, string, []*signer.Node) {
	logger.SetLevel(logger.VERBOSE)
	ctx, signers := signer.TestPrepare(require)
	mpc := signer.TestFROSTPrepareKeys(ctx, require, signers, common.CurveEdwards25519Mixin)
	chainCode := make([]byte, 32)

	root, err := os.MkdirTemp("", "safe-keeper-test-")
	require.Nil(err)
	node := testBuildNode(ctx, require, root)
	require.NotNil(node)
	timestamp, err := node.timestamp(ctx)
	require.Nil(err)
	require.Equal(time.Unix(0, node.conf.MTG.Genesis.Timestamp), timestamp)
	testSpareKeys(ctx, require, node, 0, 0, 0, common.CurveEdwards25519Mixin)

	id := uuid.Must(uuid.NewV4()).String()
	extra := append([]byte{common.RequestRoleSigner}, chainCode...)
	extra = append(extra, common.RequestFlagNone)
	out := testBuildSignerOutput(node, id, mpc, common.OperationTypeKeygenOutput, extra, common.CurveEdwards25519Mixin)
	testStep(ctx, require, node, out)
	v, err := node.store.ReadProperty(ctx, id)
	require.Nil(err)
	require.Equal("", v)
	testSpareKeys(ctx, require, node, 0, 1, 0, common.CurveEdwards25519Mixin)

	id = uuid.Must(uuid.NewV4()).String()
	observer := testMixinKernelPublicKey(testMixinKernelObserverPrivate)
	occ := make([]byte, 32)
	extra = append([]byte{common.RequestRoleObserver}, occ...)
	extra = append(extra, common.RequestFlagNone)
	out = testBuildObserverRequest(node, id, observer, common.ActionObserverAddKey, extra, common.CurveEdwards25519Mixin)
	testStep(ctx, require, node, out)
	v, err = node.store.ReadProperty(ctx, id)
	require.Nil(err)
	require.Equal("", v)
	testSpareKeys(ctx, require, node, 0, 1, 1, common.CurveEdwards25519Mixin)

	batch := byte(64)
	id = uuid.Must(uuid.NewV4()).String()
	dummy := testMixinKernelPublicKey(testMixinKernelDummyHolderPrivate)
	out = testBuildObserverRequest(node, id, dummy, common.ActionObserverRequestSignerKeys, []byte{batch}, common.CurveEdwards25519Mixin)
	testStep(ctx, require, node, out)
	for i := byte(0); i < batch; i++ {
		pid := common.UniqueId(id, fmt.Sprintf("%8d", i))
		pid = common.UniqueId(pid, fmt.Sprintf("MTG:%v:%d", node.signer.Genesis.Members, node.signer.Genesis.Threshold))
		v, _ := node.store.ReadProperty(ctx, pid)
		var om map[string]any
		json.Unmarshal([]byte(v), &om)
		b, _ := hex.DecodeString(om["memo"].(string))
		b = common.AESDecrypt(node.signerAESKey[:], b)
		o, err := common.DecodeOperation(b)
		require.Nil(err)
		require.Equal(pid, o.Id)
	}
	testSpareKeys(ctx, require, node, 0, 1, 1, common.CurveEdwards25519Mixin)

	for i := 0; i < 10; i++ {
		testMixinKernelUpdateAccountPrice(ctx, require, node)
	}
	rid, publicKey := testMixinKernelProposeAccount(ctx, require, node, mpc, observer)
	testSpareKeys(ctx, require, node, 0, 0, 0, common.CurveEdwards25519Mixin)
	testMixinKernelApproveAccount(ctx, require, node, mpc, observer, rid, publicKey)
	testSpareKeys(ctx, require, node, 0, 0, 0, common.CurveEdwards25519Mixin)
	for i := 0; i < 10; i++ {
		testMixinKernelUpdateNetworkStatus(ctx, require, node, 641117557, "2192715566293aba968675bd63a211d5489e283c2facfb19456bb51d75b80df6")
	}

	return ctx, node, mpc, signers
}

func testMixinKernelUpdateAccountPrice(ctx context.Context, require *require.Assertions, node *Node) {
	id := uuid.Must(uuid.NewV4()).String()

	extra := []byte{SafeChainMixinKernel}
	extra = append(extra, uuid.Must(uuid.FromString(testAccountPriceAssetId)).Bytes()...)
	extra = binary.BigEndian.AppendUint64(extra, testAccountPriceAmount*100000000)
	extra = binary.BigEndian.AppendUint64(extra, 10000)
	dummy := testMixinKernelPublicKey(testMixinKernelDummyHolderPrivate)
	out := testBuildObserverRequest(node, id, dummy, common.ActionObserverSetOperationParams, extra, common.CurveEdwards25519Mixin)
	testStep(ctx, require, node, out)

	plan, err := node.store.ReadLatestOperationParams(ctx, SafeChainMixinKernel, time.Now())
	require.Nil(err)
	require.Equal(testAccountPriceAssetId, plan.OperationPriceAsset)
	require.Equal(fmt.Sprint(testAccountPriceAmount), plan.OperationPriceAmount.String())
	require.Equal("0.0001", plan.TransactionMinimum.String())
}

func testMixinKernelUpdateNetworkStatus(ctx context.Context, require *require.Assertions, node *Node, blockHeight int, blockHash string) {
	id := uuid.Must(uuid.NewV4()).String()
	fee, height := 0, uint64(blockHeight)
	hash, _ := crypto.HashFromString(blockHash)

	extra := []byte{SafeChainMixinKernel}
	extra = binary.BigEndian.AppendUint64(extra, uint64(fee))
	extra = binary.BigEndian.AppendUint64(extra, height)
	extra = append(extra, hash[:]...)
	dummy := testMixinKernelPublicKey(testMixinKernelDummyHolderPrivate)
	out := testBuildObserverRequest(node, id, dummy, common.ActionObserverUpdateNetworkStatus, extra, common.CurveEdwards25519Mixin)
	testStep(ctx, require, node, out)

	info, err := node.store.ReadLatestNetworkInfo(ctx, SafeChainMixinKernel, time.Now())
	require.Nil(err)
	require.NotNil(info)
	require.Equal(byte(SafeChainMixinKernel), info.Chain)
	require.Equal(uint64(fee), info.Fee)
	require.Equal(height, info.Height)
	require.Equal(hash.String(), info.Hash)
}

func testMixinKernelRevokeTransaction(ctx context.Context, require *require.Assertions, node *Node, transactionHash string, signByObserver bool) {
	id := uuid.Must(uuid.NewV4()).String()

	tx, _ := node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateInitial, tx.State)

	var sig crypto.Signature
	ms := fmt.Sprintf("REVOKE:%s:%s", tx.RequestId, tx.TransactionHash)
	msg := mixin.HashMessageForSignature(ms)
	if signByObserver {
		key, _ := crypto.KeyFromString(testMixinKernelObserverPrivate)
		sig = key.Sign(msg)
	} else {
		key, _ := crypto.KeyFromString(testMixinKernelHolderPrivate)
		sig = key.Sign(msg)
	}
	extra := uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	extra = append(extra, sig[:]...)

	holder := testMixinKernelPublicKey(testMixinKernelHolderPrivate)
	out := testBuildObserverRequest(node, id, holder, common.ActionMixinKernelSafeRevokeTransaction, extra, common.CurveEdwards25519Mixin)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 0)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateFailed, tx.State)
}

func testMixinKernelApproveTransaction(ctx context.Context, require *require.Assertions, node *Node, transactionHash string, signers []*signer.Node) string {
	id := uuid.Must(uuid.NewV4()).String()

	tx, _ := node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateInitial, tx.State)
	safe, _ := node.store.ReadSafe(ctx, tx.Holder)

	var data struct {
		StorageTransaction crypto.Hash `json:"storage"`
	}
	json.Unmarshal([]byte(tx.Data), &data)
	v, _ := node.store.ReadProperty(ctx, data.StorageTransaction.String())
	for _, sn := range signers {
		signer.TestWriteProperty(ctx, sn, data.StorageTransaction.String(), v)
	}

	key, _ := crypto.KeyFromString(testMixinKernelHolderPrivate)
	ms := fmt.Sprintf("APPROVE:%s:%s", tx.RequestId, tx.TransactionHash)
	sig := key.Sign(mixin.HashMessageForSignature(ms))
	extra := uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	extra = append(extra, sig[:]...)

	holder := testMixinKernelPublicKey(testMixinKernelHolderPrivate)
	out := testBuildObserverRequest(node, id, holder, common.ActionMixinKernelSafeApproveTransaction, extra, common.CurveEdwards25519Mixin)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 2)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStatePending, tx.State)

	msg, _ := hex.DecodeString(requests[0].Message)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignInput, msg, common.CurveEdwards25519Mixin)
	for _, sn := range signers {
		signer.TestWriteProperty(ctx, sn, out.TransactionHash.String(), data.StorageTransaction.String())
	}
	op := signer.TestProcessOutput(ctx, require, signers, out, requests[0].RequestId)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignOutput, op.Extra, common.CurveEdwards25519Mixin)
	testStep(ctx, require, node, out)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStatePending)
	require.Len(requests, 1)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStatePending, tx.State)

	msg, _ = hex.DecodeString(requests[1].Message)
	out = testBuildSignerOutput(node, requests[1].RequestId, safe.Signer, common.OperationTypeSignInput, msg, common.CurveEdwards25519Mixin)
	for _, sn := range signers {
		signer.TestWriteProperty(ctx, sn, out.TransactionHash.String(), data.StorageTransaction.String())
	}
	op = signer.TestProcessOutput(ctx, require, signers, out, requests[1].RequestId)
	out = testBuildSignerOutput(node, requests[1].RequestId, safe.Signer, common.OperationTypeSignOutput, op.Extra, common.CurveEdwards25519Mixin)
	testStep(ctx, require, node, out)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Len(requests, 0)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStatePending)
	require.Len(requests, 0)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateDone)
	require.Len(requests, 2)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateDone, tx.State)

	signed := make(map[int][]byte)
	for _, r := range requests {
		b, _ := hex.DecodeString(r.Signature.String)
		signed[r.InputIndex] = b
	}
	mb := common.DecodeHexOrPanic(tx.RawTransaction)
	exk := crypto.Blake3Hash([]byte(common.Base91Encode(mb)))
	rid := common.UniqueId(transactionHash, hex.EncodeToString(exk[:]))
	b := testReadObserverResponse(ctx, require, node, rid, common.ActionMixinKernelSafeApproveTransaction)
	require.Equal(mb, b)

	tx, _ = node.store.ReadTransaction(ctx, tx.TransactionHash)
	ver, _ := mixin.ParsePartiallySignedTransaction(common.DecodeHexOrPanic(tx.RawTransaction))
	require.Len(ver.SignaturesMap, 2)
	require.Equal(signed[0], ver.SignaturesMap[0][0][:])
	require.Equal(signed[1], ver.SignaturesMap[1][0][:])
	signedRaw := hex.EncodeToString(ver.Marshal())
	logger.Println(signedRaw)
	return signedRaw
}

func testMixinKernelProposeTransaction(ctx context.Context, require *require.Assertions, node *Node, signer, bondId string, rid, rhash, rraw string) string {
	holder := testMixinKernelPublicKey(testMixinKernelHolderPrivate)
	observer := testMixinKernelPublicKey(testMixinKernelObserverPrivate)
	info, _ := node.store.ReadLatestNetworkInfo(ctx, SafeChainMixinKernel, time.Now())
	extra := []byte{0}
	extra = append(extra, uuid.Must(uuid.FromString(info.RequestId)).Bytes()...)
	extra = append(extra, []byte(testMixinKernelTransactionReceiver)...)
	out := testBuildHolderRequest(node, rid, holder, common.ActionMixinKernelSafeProposeTransaction, bondId, extra, decimal.NewFromFloat(0.000123))
	testStep(ctx, require, node, out)

	var view crypto.Key
	safe, _ := node.store.ReadSafe(ctx, holder)
	copy(view[:], safe.Extra)
	addr := mixin.BuildAddress(holder, signer, observer)
	require.Equal(view, addr.PrivateViewKey)

	b := testReadObserverResponse(ctx, require, node, rid, common.ActionMixinKernelSafeProposeTransaction)
	require.Equal(rraw, hex.EncodeToString(b))
	psbt, err := mixin.ParsePartiallySignedTransaction(b)
	require.Nil(err)
	require.Equal(rhash, psbt.PayloadHash().String())

	require.Len(psbt.Outputs, 2)
	main := psbt.Outputs[0]
	require.Equal("0.00012300", main.Amount.String())
	require.Len(main.Keys, 1)
	pub := crypto.ViewGhostOutputKey(main.Keys[0], &view, &main.Mask, 0)
	require.Equal(signer, pub.String())
	change := psbt.Outputs[1]
	require.Equal("0.00687700", change.Amount.String())
	require.Len(change.Keys, 1)
	pub = crypto.ViewGhostOutputKey(change.Keys[0], &view, &change.Mask, 1)
	require.Equal(signer, pub.String())

	stx, err := node.store.ReadTransaction(ctx, psbt.PayloadHash().String())
	require.Nil(err)
	require.Equal(hex.EncodeToString(psbt.Marshal()), stx.RawTransaction)
	require.Equal(common.RequestStateInitial, stx.State)

	if rid == "3e37ea1c-1455-400d-9642-f6bbcd8c744e" {
		require.Equal("a11e825b186b695bc72cdbd312ca8b03457d4c592e33dfd66fa46d226dcfcc22", main.Mask.String())
		require.Equal("2ef07340f5fd41b9fc5f106bb0df32b651c2ccee1ba66ccb9fc165da60da696d", change.Mask.String())
		require.Equal("{\"recipients\":[{\"amount\":\"0.000123\",\"receiver\":\"XINZrJcfd6QoKrR7Q31YY7gk2zvbU1qkAAZ4xBan4KQYeDq7sZ21g4WFsa2bXKoXSWy4sRvr8grSBRmXPxjDBHbF4jaik5om\"}],\"storage\":\"08b87919fb1b36270bffbc8a21ad7d9d1175ec7eb37d9cc84c3d4e5a96a0cbf0\"}", stx.Data)
	} else {
		require.Equal("369e617a18e7655e927e5f0f3805f5fd8d182888556311f626f441b02ac81a01", main.Mask.String())
		require.Equal("96e7f0d15190e22a1c07ed9faa9ecfa54c88b4bc77539ab7afc977b6a541ed69", change.Mask.String())
		require.Equal("{\"recipients\":[{\"amount\":\"0.000123\",\"receiver\":\"XINZrJcfd6QoKrR7Q31YY7gk2zvbU1qkAAZ4xBan4KQYeDq7sZ21g4WFsa2bXKoXSWy4sRvr8grSBRmXPxjDBHbF4jaik5om\"}],\"storage\":\"0f692ca9b1152706967873513dc9e518ab51b1acbf1245e5e592dce332b5ff73\"}", stx.Data)
	}
	return stx.TransactionHash
}

func testMixinKernelHolderApproveTransaction(rawTransaction string) string {
	hb := common.DecodeHexOrPanic(testBitcoinKeyHolderPrivate)
	holder, _ := btcec.PrivKeyFromBytes(hb)

	psTx, _ := bitcoin.UnmarshalPartiallySignedTransaction(common.DecodeHexOrPanic(rawTransaction))
	for idx := range psTx.UnsignedTx.TxIn {
		hash := psTx.SigHash(idx)
		sig := ecdsa.Sign(holder, hash).Serialize()
		psTx.Inputs[idx].PartialSigs = []*psbt.PartialSig{{
			PubKey:    holder.PubKey().SerializeCompressed(),
			Signature: sig,
		}}
	}
	raw := psTx.Marshal()
	return hex.EncodeToString(raw)
}

func (node *Node) testMixinKernelSignerHolderApproveTransaction(ctx context.Context, require *require.Assertions, rawTransaction string, signed map[int][]byte, signer, path string) *wire.MsgTx {
	hb := common.DecodeHexOrPanic(testBitcoinKeyHolderPrivate)
	holder, _ := btcec.PrivKeyFromBytes(hb)

	b, _ := hex.DecodeString(rawTransaction)
	psbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)
	msgTx := psbt.UnsignedTx
	for idx := range msgTx.TxIn {
		pop := msgTx.TxIn[idx].PreviousOutPoint
		hash := psbt.SigHash(idx)
		utxo, _, _ := node.store.ReadBitcoinUTXO(ctx, pop.Hash.String(), int(pop.Index))
		msig := signed[idx]
		if msig == nil {
			continue
		}

		msig = append(msig, byte(bitcoin.SigHashType))
		der, _ := ecdsa.ParseDERSignature(msig[:len(msig)-1])
		pub, _ := node.deriveBIP32WithPath(ctx, signer, common.DecodeHexOrPanic(path))
		signer, _ := btcutil.NewAddressPubKey(common.DecodeHexOrPanic(pub), &chaincfg.MainNetParams)
		require.True(der.Verify(hash, signer.PubKey()))

		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, []byte{})
		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, msig)

		signature := ecdsa.Sign(holder, hash)
		sig := append(signature.Serialize(), byte(bitcoin.SigHashType))
		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)
		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, utxo.Script)
	}

	return msgTx
}

func testMixinKernelObserverHolderDeposit(ctx context.Context, require *require.Assertions, node *Node, signer, observer string, input *mixin.Input, t int) {
	id := uuid.Must(uuid.NewV4()).String()
	hash, _ := crypto.HashFromString(input.TransactionHash)
	iam := input.Amount.Mul(decimal.New(1, mixin.ValuePrecision))
	if !iam.IsInteger() {
		panic(input.Amount.String())
	}
	extra := []byte{SafeChainMixinKernel}
	extra = append(extra, uuid.Must(uuid.FromString(SafeMixinKernelAssetId)).Bytes()...)
	extra = append(extra, hash[:]...)
	extra = binary.BigEndian.AppendUint64(extra, uint64(input.Index))
	extra = append(extra, iam.BigInt().Bytes()...)

	holder := testMixinKernelPublicKey(testMixinKernelHolderPrivate)

	out := testBuildObserverRequest(node, id, holder, common.ActionObserverHolderDeposit, extra, common.CurveEdwards25519Mixin)
	testStep(ctx, require, node, out)

	mainInputs, err := node.store.ListAllMixinKernelUTXOsForHolderAndAsset(ctx, holder, SafeMixinKernelAssetId)
	require.Nil(err)
	require.Len(mainInputs, t)
	utxo := mainInputs[t-1]
	require.Equal(uint32(input.Index), utxo.Index)
	require.Equal(input.Amount, utxo.Amount)
	require.Equal(hash.String(), utxo.TransactionHash)
}

func testMixinKernelProposeAccount(ctx context.Context, require *require.Assertions, node *Node, signer, observer string) (string, string) {
	id := uuid.Must(uuid.NewV4()).String()
	holder := testMixinKernelPublicKey(testMixinKernelHolderPrivate)
	extra := testRecipient()
	price := decimal.NewFromFloat(testAccountPriceAmount)
	out := testBuildHolderRequest(node, id, holder, common.ActionMixinKernelSafeProposeAccount, testAccountPriceAssetId, extra, price)
	testStep(ctx, require, node, out)
	b := testReadObserverResponse(ctx, require, node, id, common.ActionMixinKernelSafeProposeAccount)
	wsa, err := mixin.ParseAddress(string(b))
	require.Nil(err)
	require.Equal(testMixinKernelAddress, wsa.String())

	safe, err := node.store.ReadSafeProposal(ctx, id)
	require.Nil(err)
	require.Equal(id, safe.RequestId)
	require.Equal(holder, safe.Holder)
	require.Equal(signer, safe.Signer)
	require.Equal(observer, safe.Observer)
	public := mixin.BuildAddress(holder, signer, observer)
	require.Equal(testMixinKernelAddress, public.String())
	require.Equal(public.String(), safe.Address)
	require.Equal(byte(1), safe.Threshold)
	require.Len(safe.Receivers, 1)
	require.Equal(testSafeBondReceiverId, safe.Receivers[0])

	return id, wsa.String()
}

func testMixinKernelApproveAccount(ctx context.Context, require *require.Assertions, node *Node, signer, observer string, rid, publicKey string) {
	id := uuid.Must(uuid.NewV4()).String()
	holder := testMixinKernelPublicKey(testMixinKernelHolderPrivate)
	ms := fmt.Sprintf("APPROVE:%s:%s", rid, publicKey)
	hash := mixin.HashMessageForSignature(ms)
	hp, _ := crypto.KeyFromString(testMixinKernelHolderPrivate)
	signature := hp.Sign(hash)
	extra := uuid.FromStringOrNil(rid).Bytes()
	extra = append(extra, signature[:]...)
	out := testBuildObserverRequest(node, id, holder, common.ActionMixinKernelSafeApproveAccount, extra, common.CurveEdwards25519Mixin)
	testStep(ctx, require, node, out)
	b := testReadObserverResponse(ctx, require, node, id, common.ActionMixinKernelSafeApproveAccount)
	wsa, err := mixin.ParseAddress(string(b))
	require.Nil(err)
	require.Equal(testMixinKernelAddress, wsa.String())

	safe, err := node.store.ReadSafe(ctx, holder)
	require.Nil(err)
	require.Equal(id, safe.RequestId)
	require.Equal(holder, safe.Holder)
	require.Equal(signer, safe.Signer)
	require.Equal(observer, safe.Observer)
	public := mixin.BuildAddress(holder, signer, observer)
	require.Equal(testMixinKernelAddress, public.String())
	require.Equal(public.String(), safe.Address)
	require.Equal(byte(1), safe.Threshold)
	require.Len(safe.Receivers, 1)
	require.Equal(testSafeBondReceiverId, safe.Receivers[0])
	var view crypto.Key
	copy(view[:], safe.Extra)
	require.Equal(view, public.PrivateViewKey)
}

func testMixinKernelPublicKey(priv string) string {
	key, _ := crypto.KeyFromString(priv)
	return key.Public().String()
}
