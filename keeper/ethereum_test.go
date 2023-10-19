package keeper

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	mc "github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/signer"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

const (
	testEthereumSafeAddress    = "0x0cDb2d45335bDaf2c915Ec409956356571b9cA5B"
	testEthereumKeyHolder      = "6421d5ce0fd415397fdd2978733852cee7ad44f28d87cd96038460907e2ffb18"
	testEthereumKeyObserver    = "ff29332c230fdd78cfee84e10bc5edc9371a6a593ccafaf08e115074e7de2b89"
	testEthereumKeyDummyHolder = "169b5ed2deaa8ea7171e60598332560b1d01e8a28243510335196acd62fd3a71"

	testEthereumBondAssetId         = "7ee89140-e88a-3d8d-89d1-d60cf421d53f"
	testEthereumTransactionReceiver = "0xA03A8590BB3A2cA5c747c8b99C63DA399424a055"
)

func TestUnpackSafeTransactionInput(t *testing.T) {
	require := require.New(t)
	hash := "0xd030120e4840dff693e85cb2d82c35a46917e0703de774f909e7ba6eaca40fbf"
	tx, _ := ethereum.RPCGetTransactionByHash("https://geth.mvm.dev", hash)
	st, err := ethereum.UnpackSafeTransactionInput("https://geth.mvm.dev", tx, SafeChainMVM)
	require.Nil(err)
	require.NotNil(st)

	holder, err := testEthereumPublicKey(testEthereumKeyHolder)
	require.Nil(err)
	observer, err := testEthereumPublicKey(testEthereumKeyObserver)
	require.Nil(err)

	offset := 0
	length := 65
	pubs := []string{holder, observer}
	sigs := make(map[string][]byte, 2)
	for offset+length <= len(st.Signature) {
		end := offset + length
		sig := st.Signature[offset:end]
		for _, pub := range pubs {
			err = ethereum.VerifyMessageSignature(pub, st.Message, sig)
			if err == nil {
				sigs[pub] = sig
			}
		}
		offset += length
	}
	require.NotNil(sigs[holder])
	require.NotNil(sigs[observer])
}

func TestEthereumKeeper(t *testing.T) {
	require := require.New(t)
	ctx, node, mpc, signers := testEthereumPrepare(require)

	observer, err := testEthereumPublicKey(testEthereumKeyObserver)
	require.Nil(err)
	bondId := testDeployBondContract(ctx, require, node, testEthereumSafeAddress, SafeMVMChainId)
	require.Equal(testEthereumBondAssetId, bondId)
	node.ProcessOutput(ctx, &mtg.Output{AssetID: bondId, Amount: decimal.NewFromInt(100000000000000), CreatedAt: time.Now()})
	testEthereumObserverHolderDeposit(ctx, require, node, mpc, observer, "9d990e0a07c4f45489f9e03ab28a0f1f14ff5deb06de6dd85da20255753ff3ef", bondId, "100000000000000")

	txHash := testEthereumProposeTransaction(ctx, require, node, mpc, bondId, "3e37ea1c-1455-400d-9642-f6bbcd8c744e")
	testEthereumRevokeTransaction(ctx, require, node, txHash, false)
	txHash = testEthereumProposeTransaction(ctx, require, node, mpc, bondId, "3e37ea1c-1455-400d-9642-f6bbcd8c7441")
	testEthereumApproveTransaction(ctx, require, node, txHash, signers)
}

func TestEthereumKeeperCloseAccountWithSignerObserver(t *testing.T) {
	require := require.New(t)
	ctx, node, mpc, signers := testEthereumPrepare(require)
	for i := 0; i < 10; i++ {
		testEthereumUpdateNetworkStatus(ctx, require, node, 43690750, "b133d48e366f40e97d8f63aa7a28fa31f477aa1dc87f9bd09795138c1540366a")
	}

	observer, err := testEthereumPublicKey(testEthereumKeyObserver)
	require.Nil(err)
	bondId := testDeployBondContract(ctx, require, node, testEthereumSafeAddress, SafeMVMChainId)
	require.Equal(testEthereumBondAssetId, bondId)
	node.ProcessOutput(ctx, &mtg.Output{AssetID: bondId, Amount: decimal.NewFromInt(100000000000000), CreatedAt: time.Now()})
	testEthereumObserverHolderDeposit(ctx, require, node, mpc, observer, "9d990e0a07c4f45489f9e03ab28a0f1f14ff5deb06de6dd85da20255753ff3ef", bondId, "100000000000000")

	txHash := testEthereumProposeTransaction(ctx, require, node, mpc, bondId, "3e37ea1c-1455-400d-9642-f6bbcd8c744e")

	id := uuid.Must(uuid.NewV4()).String()
	tx, _ := node.store.ReadTransaction(ctx, txHash)
	require.Equal(common.RequestStateInitial, tx.State)
	raw, _ := hex.DecodeString(tx.RawTransaction)
	st, err := ethereum.UnmarshalSafeTransaction(raw)

	safe, _ := node.store.ReadSafe(ctx, tx.Holder)
	_, pubs, err := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	require.Nil(err)
	for i, pub := range pubs {
		if pub == observer {
			sig, err := testEthereumSignMessage(require, testEthereumKeyObserver, st.Message)
			require.Nil(err)
			st.Signatures[i] = sig
		}
	}

	raw = st.Marshal()
	ref := mc.NewHash(raw)
	err = node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(raw))
	require.Nil(err)
	extra := uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	extra = append(extra, ref[:]...)
	out := testBuildObserverRequest(node, id, tx.Holder, common.ActionEthereumSafeCloseAccount, extra, common.CurveSecp256k1ECDSAMVM)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, tx.TransactionHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, tx.TransactionHash)
	require.Equal(common.RequestStatePending, tx.State)

	msg, _ := hex.DecodeString(requests[0].Message)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignInput, msg, common.CurveSecp256k1ECDSAMVM)
	op := signer.TestProcessOutput(ctx, require, signers, out, requests[0].RequestId)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignOutput, op.Extra, common.CurveSecp256k1ECDSAMVM)
	testStep(ctx, require, node, out)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, tx.TransactionHash, common.RequestStatePending)
	require.Len(requests, 0)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, tx.TransactionHash, common.RequestStateInitial)
	require.Len(requests, 0)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, tx.TransactionHash, common.RequestStateDone)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, tx.TransactionHash)
	require.Equal(common.RequestStateDone, tx.State)

	mb := common.DecodeHexOrPanic(tx.RawTransaction)
	exk := mc.Blake3Hash([]byte(common.Base91Encode(mb)))
	rid := common.UniqueId(tx.TransactionHash, hex.EncodeToString(exk[:]))
	b := testReadObserverResponse(ctx, require, node, rid, common.ActionEthereumSafeApproveTransaction)
	require.Equal(mb, b)

	rpc, _ := node.ethereumParams(SafeChainMVM)
	st, _ = ethereum.UnmarshalSafeTransaction(mb)
	success, err := st.ValidTransaction(rpc)
	require.Nil(err)
	require.True(success)
}

func TestEthereumKeeperCloseAccountWithHolderObserver(t *testing.T) {
	require := require.New(t)
	ctx, node, mpc, _ := testEthereumPrepare(require)
	for i := 0; i < 10; i++ {
		testEthereumUpdateNetworkStatus(ctx, require, node, 43690750, "b133d48e366f40e97d8f63aa7a28fa31f477aa1dc87f9bd09795138c1540366a")
	}

	holder, err := testEthereumPublicKey(testEthereumKeyHolder)
	require.Nil(err)
	observer, err := testEthereumPublicKey(testEthereumKeyObserver)
	require.Nil(err)
	bondId := testDeployBondContract(ctx, require, node, testEthereumSafeAddress, SafeMVMChainId)
	require.Equal(testEthereumBondAssetId, bondId)
	node.ProcessOutput(ctx, &mtg.Output{AssetID: bondId, Amount: decimal.NewFromInt(100000000000000), CreatedAt: time.Now()})
	testEthereumObserverHolderDeposit(ctx, require, node, mpc, observer, "9d990e0a07c4f45489f9e03ab28a0f1f14ff5deb06de6dd85da20255753ff3ef", bondId, "100000000000000")

	rpc, _ := node.ethereumParams(SafeChainMVM)
	chainId := ethereum.GetEvmChainID(SafeChainMVM)
	st, err := ethereum.CreateTransaction(ctx, false, rpc, chainId, testEthereumSafeAddress, testEthereumTransactionReceiver, "100000000000000", nil)
	require.Nil(err)

	safe, _ := node.store.ReadSafe(ctx, holder)
	_, pubs, err := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	require.Nil(err)
	for i, pub := range pubs {
		var sig []byte
		if pub == observer {
			sig, err = testEthereumSignMessage(require, testEthereumKeyObserver, st.Message)
			require.Nil(err)
			st.Signatures[i] = sig
		}
		if pub == holder {
			sig, err = testEthereumSignMessage(require, testEthereumKeyHolder, st.Message)
			require.Nil(err)
			st.Signatures[i] = sig
		}
	}
	raw := st.Marshal()

	ref := mc.NewHash(raw)
	err = node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(raw))
	require.Nil(err)
	extra := uuid.Nil.Bytes()
	extra = append(extra, ref[:]...)
	id := uuid.Must(uuid.NewV4()).String()
	out := testBuildObserverRequest(node, id, holder, common.ActionEthereumSafeCloseAccount, extra, common.CurveSecp256k1ECDSAMVM)
	testStep(ctx, require, node, out)

	tx, err := node.store.ReadTransaction(ctx, st.Hash(testEthereumSafeAddress))
	require.Nil(err)
	require.Equal(common.RequestStateDone, tx.State)
	safe, err = node.store.ReadSafe(ctx, tx.Holder)
	require.Nil(err)
	require.Equal(common.RequestStateFailed, int(safe.State))

	raw, _ = hex.DecodeString(tx.RawTransaction)
	stx, _ := ethereum.UnmarshalSafeTransaction(raw)
	success, err := stx.ValidTransaction(rpc)
	require.Nil(err)
	require.True(success)
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
		testEthereumUpdateNetworkStatus(ctx, require, node, 43446223, "977f74ac401f5dd6803e883eec8fe35e3d90b83c869aada7cf77791c4c46004e")
	}
	return ctx, node, mpc, signers
}

func testEthereumProposeTransaction(ctx context.Context, require *require.Assertions, node *Node, signer, bondId string, rid string) string {
	holder := testPublicKey(testEthereumKeyHolder)
	info, err := node.store.ReadLatestNetworkInfo(ctx, SafeChainMVM, time.Now())
	require.Nil(err)
	extra := []byte{0}
	extra = append(extra, uuid.Must(uuid.FromString(info.RequestId)).Bytes()...)
	extra = append(extra, []byte(testEthereumTransactionReceiver)...)
	out := testBuildHolderRequest(node, rid, holder, common.ActionEthereumSafeProposeTransaction, bondId, extra, decimal.NewFromFloat(0.0001))
	testStep(ctx, require, node, out)

	b := testReadObserverResponse(ctx, require, node, rid, common.ActionEthereumSafeProposeTransaction)
	t, err := ethereum.UnmarshalSafeTransaction(b[16:])
	require.Nil(err)

	amt := decimal.NewFromBigInt(t.Value, -ethereum.ValuePrecision)
	require.Equal("0.0001", amt.String())
	require.Equal(testEthereumTransactionReceiver, t.Destination.Hex())
	require.Equal(testEthereumSafeAddress, t.SafeAddress)

	stx, err := node.store.ReadTransaction(ctx, t.Hash(rid))
	require.Nil(err)
	require.Equal(hex.EncodeToString(t.Marshal()), stx.RawTransaction)
	require.Equal("[{\"amount\":\"0.0001\",\"receiver\":\"0xA03A8590BB3A2cA5c747c8b99C63DA399424a055\"}]", stx.Data)
	require.Equal(common.RequestStateInitial, stx.State)

	return stx.TransactionHash
}

func testEthereumRevokeTransaction(ctx context.Context, require *require.Assertions, node *Node, transactionHash string, signByObserver bool) {
	id := uuid.Must(uuid.NewV4()).String()

	tx, _ := node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateInitial, tx.State)

	key := testEthereumKeyHolder
	if signByObserver {
		key = testEthereumKeyObserver
	}
	ms := fmt.Sprintf("REVOKE:%s:%s", tx.RequestId, tx.TransactionHash)
	sig, err := testEthereumSignMessage(require, key, []byte(ms))
	require.Nil(err)

	extra := uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	extra = append(extra, sig...)

	out := testBuildObserverRequest(node, id, testPublicKey(testEthereumKeyHolder), common.ActionEthereumSafeRevokeTransaction, extra, common.CurveSecp256k1ECDSAMVM)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 0)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateFailed, tx.State)
}

func testEthereumApproveTransaction(ctx context.Context, require *require.Assertions, node *Node, transactionHash string, signers []*signer.Node) {
	id := uuid.Must(uuid.NewV4()).String()

	tx, _ := node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateInitial, tx.State)
	raw, err := hex.DecodeString(tx.RawTransaction)
	require.Nil(err)
	t, err := ethereum.UnmarshalSafeTransaction(raw)
	require.Nil(err)

	safe, _ := node.store.ReadSafe(ctx, tx.Holder)
	_, pubs, err := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	require.Nil(err)

	holder, err := testEthereumPublicKey(testEthereumKeyHolder)
	require.Nil(err)
	for i, pub := range pubs {
		if pub == holder {
			sig, err := testEthereumSignMessage(require, testEthereumKeyHolder, t.Message)
			require.Nil(err)
			t.Signatures[i] = sig
		}
	}

	raw = t.Marshal()
	ref := mc.NewHash(raw)
	err = node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(raw))
	require.Nil(err)
	extra := uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	extra = append(extra, ref[:]...)

	out := testBuildObserverRequest(node, id, testPublicKey(testEthereumKeyHolder), common.ActionEthereumSafeApproveTransaction, extra, common.CurveSecp256k1ECDSAMVM)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStatePending, tx.State)

	msg, _ := hex.DecodeString(requests[0].Message)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignInput, msg, common.CurveSecp256k1ECDSAMVM)
	op := signer.TestProcessOutput(ctx, require, signers, out, requests[0].RequestId)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignOutput, op.Extra, common.CurveSecp256k1ECDSAMVM)
	testStep(ctx, require, node, out)

	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateDone, tx.State)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Len(requests, 0)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStatePending)
	require.Len(requests, 0)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateDone)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateDone, tx.State)

	rpc, _ := node.ethereumParams(SafeChainMVM)
	raw, _ = hex.DecodeString(tx.RawTransaction)
	t, _ = ethereum.UnmarshalSafeTransaction(raw)

	valid, err := t.ValidTransaction(rpc)
	require.Nil(err)
	require.True(valid)
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

	tx, err := node.store.ReadTransaction(ctx, gs.TxHash)
	require.Nil(err)
	raw, err := hex.DecodeString(tx.RawTransaction)
	require.Nil(err)
	t, err := ethereum.UnmarshalSafeTransaction(raw)
	require.Nil(err)
	signature, err := testEthereumSignMessage(require, testEthereumKeyHolder, t.Message)
	require.Nil(err)

	extra := uuid.FromStringOrNil(rid).Bytes()
	extra = append(extra, signature[:]...)
	out := testBuildObserverRequest(node, approveRequestId, holder, common.ActionEthereumSafeApproveAccount, extra, common.CurveSecp256k1ECDSAMVM)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, gs.TxHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, gs.TxHash)
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

func testEthereumObserverHolderDeposit(ctx context.Context, require *require.Assertions, node *Node, signer, observer, txHash, asset_id, balance string) {
	id := uuid.Must(uuid.NewV4()).String()
	amt, err := decimal.NewFromString(balance)
	require.Nil(err)
	b, err := hex.DecodeString(txHash)
	require.Nil(err)
	extra := []byte{SafeChainMVM}
	extra = append(extra, uuid.Must(uuid.FromString(SafeMVMChainId)).Bytes()...)
	extra = append(extra, b...)
	extra = binary.BigEndian.AppendUint64(extra, uint64(0))
	extra = append(extra, amt.BigInt().Bytes()...)

	holder := testPublicKey(testEthereumKeyHolder)
	out := testBuildObserverRequest(node, id, holder, common.ActionObserverHolderDeposit, extra, common.CurveSecp256k1ECDSAMVM)
	testStep(ctx, require, node, out)

	safeBalance, err := node.store.ReadEthereumBalance(ctx, testEthereumSafeAddress, SafeMVMChainId)
	require.Nil(err)
	require.Equal(balance, safeBalance.Balance.String())
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
	require.Equal(hex.EncodeToString(hash), info.Hash[2:])
}

func testEthereumUpdateAccountPrice(ctx context.Context, require *require.Assertions, node *Node) {
	id := uuid.Must(uuid.NewV4()).String()

	extra := []byte{SafeChainMVM}
	extra = append(extra, uuid.Must(uuid.FromString(testAccountPriceAssetId)).Bytes()...)
	extra = binary.BigEndian.AppendUint64(extra, testAccountPriceAmount*100000000)
	extra = binary.BigEndian.AppendUint64(extra, 10000)
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
