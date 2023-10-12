package keeper

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/signer"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

const (
	testEthereumSafeAddress    = "0xEf1dfD07d60A0000A6DDE2F399ed5E8d5D335bDE"
	testEthereumKeyHolder      = "4cb7437a31a724c7231f83c01f865bf13fc65725cb6219ac944321f484bf80a2"
	testEthereumKeyObserver    = "6421d5ce0fd415397fdd2978733852cee7ad44f28d87cd96038460907e2ffb18"
	testEthereumKeyDummyHolder = "169b5ed2deaa8ea7171e60598332560b1d01e8a28243510335196acd62fd3a71"

	testEthereumBondAssetId         = "1cec68e2-3f14-3f1d-a46b-3d37688c95bd"
	testEthereumTransactionReceiver = "0xA03A8590BB3A2cA5c747c8b99C63DA399424a055"
)

func TestEthereumKeeper(t *testing.T) {
	require := require.New(t)
	ctx, node, _, _ := testEthereumPrepare(require)

	bondId := testDeployBondContract(ctx, require, node, testEthereumSafeAddress, SafeMVMChainId)
	require.Equal(testEthereumBondAssetId, bondId)

	observer, err := testEthereumPublicKey(testEthereumKeyObserver)
	require.Nil(err)
	fmt.Println(observer)
}

func testEthereumPrepare(require *require.Assertions) (context.Context, *Node, string, []*signer.Node) {
	logger.SetLevel(logger.VERBOSE)
	ctx, signers := signer.TestPrepare(require)
	mpc, cc := signer.TestCMPPrepareKeys(ctx, require, signers, common.CurveSecp256k1ECDSAMVM)
	chainCode := common.DecodeHexOrPanic(cc)

	root, err := os.MkdirTemp("", "safe-keeper-test-")
	require.Nil(err)
	node := testBuildNode(ctx, require, root)
	require.NotNil(node)
	timestamp, err := node.timestamp(ctx)
	require.Nil(err)
	require.Equal(time.Unix(0, node.conf.MTG.Genesis.Timestamp), timestamp)
	testSpareKeys(ctx, require, node, 0, 0, 0, common.CurveSecp256k1ECDSAMVM)

	id := uuid.Must(uuid.NewV4()).String()
	extra := append([]byte{common.RequestRoleSigner}, chainCode...)
	extra = append(extra, common.RequestFlagNone)
	out := testBuildSignerOutput(node, id, mpc, common.OperationTypeKeygenOutput, extra, common.CurveSecp256k1ECDSAEthereum)
	testStep(ctx, require, node, out)
	v, err := node.store.ReadProperty(ctx, id)
	require.Nil(err)
	require.Equal("", v)
	testSpareKeys(ctx, require, node, 0, 1, 0, common.CurveSecp256k1ECDSAEthereum)

	id = uuid.Must(uuid.NewV4()).String()
	observer, err := testEthereumPublicKey(testEthereumKeyObserver)
	require.Nil(err)
	occ := make([]byte, 32)
	extra = append([]byte{common.RequestRoleObserver}, occ...)
	extra = append(extra, common.RequestFlagNone)
	out = testBuildObserverRequest(node, id, observer, common.ActionObserverAddKey, extra, common.CurveSecp256k1ECDSAEthereum)
	testStep(ctx, require, node, out)
	v, err = node.store.ReadProperty(ctx, id)
	require.Nil(err)
	require.Equal("", v)
	testSpareKeys(ctx, require, node, 0, 1, 1, common.CurveSecp256k1ECDSAEthereum)

	batch := byte(64)
	id = uuid.Must(uuid.NewV4()).String()
	dummy, err := testEthereumPublicKey(testEthereumKeyHolder)
	require.Nil(err)
	out = testBuildObserverRequest(node, id, dummy, common.ActionObserverRequestSignerKeys, []byte{batch}, common.CurveSecp256k1ECDSAMVM)
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
	testSpareKeys(ctx, require, node, 0, 1, 1, common.CurveSecp256k1ECDSAEthereum)

	for i := 0; i < 10; i++ {
		testEthereumUpdateAccountPrice(ctx, require, node)
	}
	rid, safe := testEthereumProposeAccount(ctx, require, node, mpc, observer)
	testSpareKeys(ctx, require, node, 0, 0, 0, common.CurveSecp256k1ECDSAEthereum)
	testEthereumApproveAccount(ctx, require, node, rid, safe, signers, mpc, observer)
	testSpareKeys(ctx, require, node, 0, 0, 0, common.CurveSecp256k1ECDSAMVM)
	for i := 0; i < 10; i++ {
		testEthereumUpdateNetworkStatus(ctx, require, node, 43084096, "e738f3e9584313e1cba72113985d55473cd1ffc5048b22dc075f3b3860dd019b")
	}
	return ctx, node, mpc, signers
}

func testEthereumProposeAccount(ctx context.Context, require *require.Assertions, node *Node, signer, observer string) (string, *ethereum.GnosisSafe) {
	id := uuid.Must(uuid.NewV4()).String()
	holder, err := testEthereumPublicKey(testEthereumKeyHolder)
	require.Nil(err)
	extra := testRecipient()
	price := decimal.NewFromFloat(testAccountPriceAmount)
	out := testBuildHolderRequest(node, id, holder, common.ActionEthereumSafeProposeAccount, testAccountPriceAssetId, extra, price)
	testStep(ctx, require, node, out)
	b := testReadObserverResponse(ctx, require, node, id, common.ActionEthereumSafeProposeAccount)
	gs, err := ethereum.UnmarshalGnosisSafe(b)
	require.Nil(err)
	require.Equal(testEthereumSafeAddress, gs.Address)

	safe, err := node.store.ReadSafeProposal(ctx, id)
	require.Nil(err)
	require.Equal(id, safe.RequestId)
	require.Equal(holder, safe.Holder)
	require.Equal(signer, safe.Signer)
	require.Equal(observer, safe.Observer)

	owners, _, err := ethereum.GetSortedSafeOwners(holder, signer, observer)
	require.Nil(err)
	addr := ethereum.GetSafeAccountAddress(owners, 2)
	require.Nil(err)
	require.Equal(testEthereumSafeAddress, addr.Hex())
	require.Equal(addr.Hex(), safe.Address)
	require.Equal(byte(1), safe.Threshold)
	require.Len(safe.Receivers, 1)
	require.Equal(testSafeBondReceiverId, safe.Receivers[0])

	return id, gs
}

func testEthereumApproveAccount(ctx context.Context, require *require.Assertions, node *Node, rid string, gs *ethereum.GnosisSafe, signers []*signer.Node, safeSigner, safeObserver string) {
	approveRequestId := uuid.Must(uuid.NewV4()).String()
	holder, err := testEthereumPublicKey(testEthereumKeyHolder)
	require.Nil(err)
	sp, err := node.store.ReadSafeProposalByAddress(ctx, gs.Address)
	require.Nil(err)

	hash, err := hex.DecodeString(gs.TxHash)
	require.Nil(err)
	signature, err := testEthereumSignMessage(require, testEthereumKeyHolder, hash)
	require.Nil(err)

	extra := uuid.FromStringOrNil(rid).Bytes()
	extra = append(extra, signature[:]...)
	out := testBuildObserverRequest(node, approveRequestId, holder, common.ActionEthereumSafeApproveAccount, extra, common.CurveSecp256k1ECDSAMVM)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, gs.TxHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 1)
	tx, _ := node.store.ReadTransaction(ctx, gs.TxHash)
	require.Equal(common.RequestStatePending, tx.State)

	msg, _ := hex.DecodeString(requests[0].Message)
	out = testBuildSignerOutput(node, requests[0].RequestId, sp.Signer, common.OperationTypeSignInput, msg, common.CurveSecp256k1ECDSAMVM)
	op := signer.TestProcessOutput(ctx, require, signers, out, requests[0].RequestId)
	out = testBuildSignerOutput(node, requests[0].RequestId, sp.Signer, common.OperationTypeSignOutput, op.Extra, common.CurveSecp256k1ECDSAMVM)
	testStep(ctx, require, node, out)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, gs.TxHash, common.RequestStateDone)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, gs.TxHash)
	require.Equal(common.RequestStateDone, tx.State)

	id := common.UniqueId(requests[0].RequestId, gs.Address)
	r := testReadObserverResponse(ctx, require, node, id, common.ActionEthereumSafeApproveAccount)
	wsa, err := ethereum.UnmarshalGnosisSafe(r)
	require.Equal(testEthereumSafeAddress, wsa.Address)

	safe, err := node.store.ReadSafe(ctx, holder)
	require.Nil(err)
	require.Equal(approveRequestId, safe.RequestId)
	require.Equal(holder, safe.Holder)
	require.Equal(safeSigner, safe.Signer)
	require.Equal(safeObserver, safe.Observer)
	require.Equal(gs.Address, safe.Address)
	require.Equal(byte(1), safe.Threshold)
	require.Len(safe.Receivers, 1)
	require.Equal(testSafeBondReceiverId, safe.Receivers[0])
}

func testEthereumUpdateNetworkStatus(ctx context.Context, require *require.Assertions, node *Node, blockHeight int, blockHash string) {
	id := uuid.Must(uuid.NewV4()).String()
	fee, height := 0, uint64(blockHeight)
	hash, err := hex.DecodeString(blockHash)
	require.Nil(err)

	extra := []byte{SafeChainMVM}
	extra = binary.BigEndian.AppendUint64(extra, uint64(fee))
	extra = binary.BigEndian.AppendUint64(extra, height)
	extra = append(extra, hash[:]...)
	dummy, err := testEthereumPublicKey(testEthereumKeyDummyHolder)
	require.Nil(err)
	out := testBuildObserverRequest(node, id, dummy, common.ActionObserverUpdateNetworkStatus, extra, common.CurveSecp256k1ECDSAMVM)
	testStep(ctx, require, node, out)

	info, err := node.store.ReadLatestNetworkInfo(ctx, SafeChainMVM, time.Now())
	require.Nil(err)
	require.NotNil(info)
	require.Equal(byte(SafeChainMVM), info.Chain)
	require.Equal(uint64(fee), info.Fee)
	require.Equal(height, info.Height)
	require.Equal(hex.EncodeToString(hash), info.Hash)
}

func testEthereumUpdateAccountPrice(ctx context.Context, require *require.Assertions, node *Node) {
	id := uuid.Must(uuid.NewV4()).String()

	extra := []byte{SafeChainMVM}
	extra = append(extra, uuid.Must(uuid.FromString(testAccountPriceAssetId)).Bytes()...)
	extra = binary.BigEndian.AppendUint64(extra, testAccountPriceAmount*1000000000000000000)
	extra = binary.BigEndian.AppendUint64(extra, 100000000000000)
	dummy, err := testEthereumPublicKey(testEthereumKeyHolder)
	require.Nil(err)
	out := testBuildObserverRequest(node, id, dummy, common.ActionObserverSetOperationParams, extra, common.CurveSecp256k1ECDSAMVM)
	testStep(ctx, require, node, out)

	plan, err := node.store.ReadLatestOperationParams(ctx, SafeChainMVM, time.Now())
	require.Nil(err)
	require.Equal(testAccountPriceAssetId, plan.OperationPriceAsset)
	require.Equal(fmt.Sprint(testAccountPriceAmount), plan.OperationPriceAmount.String())
	require.Equal("0.0001", plan.TransactionMinimum.String())
}

func testEthereumSignMessage(require *require.Assertions, priv string, message []byte) ([]byte, error) {
	private, err := crypto.HexToECDSA(priv)
	if err != nil {
		return nil, err
	}
	publicKey := private.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	pub := crypto.CompressPubkey(publicKeyECDSA)

	hash := crypto.Keccak256Hash([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)))
	signature, err := crypto.Sign(hash.Bytes(), private)
	if err != nil {
		return nil, err
	}
	signed := crypto.VerifySignature(pub, hash.Bytes(), signature[:64])
	require.True(signed)

	// Golang returns the recovery ID in the last byte instead of v
	// v = 27 + rid
	signature[64] += 27
	hasPrefix := testIsTxHashSignedWithPrefix(priv, hash.Bytes(), signature)
	if hasPrefix {
		signature[64] += 4
	}
	return signature, nil
}

func testIsTxHashSignedWithPrefix(priv string, hash, signature []byte) bool {
	recoveredData, err := crypto.Ecrecover(hash, signature)
	if err != nil {
		return params.TestRules.IsEIP150
	}
	recoveredPub, err := crypto.UnmarshalPubkey(recoveredData)
	if err != nil {
		return true
	}
	recoveredAddress := crypto.PubkeyToAddress(*recoveredPub).Hex()
	address, err := ethereumAddressFromPriv(priv)
	if err != nil {
		return true
	}
	return recoveredAddress != address
}

func ethereumAddressFromPriv(priv string) (string, error) {
	privateKey, err := crypto.HexToECDSA(priv)
	if err != nil {
		return "", err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)

	addr := crypto.PubkeyToAddress(*publicKeyECDSA)
	return addr.String(), nil
}

func testEthereumPublicKey(priv string) (string, error) {
	privateKey, err := crypto.HexToECDSA(priv)
	if err != nil {
		return "", err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)

	return hex.EncodeToString(crypto.CompressPubkey(publicKeyECDSA)), nil
}
