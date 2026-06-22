package keeper

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	mc "github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/MixinNetwork/safe/signer"
	gc "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

const (
	testEthereumSafeAddress    = "0x346607eb15821A4E194628444F3705c26C8E6eBe"
	testEthereumKeyHolder      = "6421d5ce0fd415397fdd2978733852cee7ad44f28d87cd96038460907e2ffb18"
	testEthereumKeyObserver    = "ff29332c230fdd78cfee84e10bc5edc9371a6a593ccafaf08e115074e7de2b89"
	testEthereumKeyDummyHolder = "169b5ed2deaa8ea7171e60598332560b1d01e8a28243510335196acd62fd3a71"

	testEthereumBondAssetId         = "08823f4a-6fd4-311e-8ddd-9478e163cf91"
	testEthereumUSDTAssetId         = "218bc6f4-7927-3f8e-8568-3a3725b74361"
	testEthereumUSDTBondAssetId     = "edc249f5-d792-3091-a359-23c67ce0d595"
	testEthereumUSDTAddress         = "0xc2132D05D31c914a87C6611C10748AEb04B58e8F"
	testEthereumTransactionReceiver = "0xA03A8590BB3A2cA5c747c8b99C63DA399424a055"
)

func TestEthereumDepositKeeper(t *testing.T) {
	require := require.New(t)
	ctx, node, db, _, _ := testEthereumPrepare(require)
	req := &common.Request{
		Id:     uuid.Must(uuid.NewV4()).String(),
		State:  common.RequestStateInitial,
		Role:   common.RequestRoleObserver,
		Output: &mtg.Action{UnifiedOutput: mtg.UnifiedOutput{OutputId: uuid.Must(uuid.NewV4()).String()}},
	}
	err := node.store.WriteRequestIfNotExist(ctx, req)
	require.Nil(err)
	err = node.store.WriteNetworkInfoFromRequest(ctx, &store.NetworkInfo{
		RequestId: req.Id,
		Chain:     common.SafeChainPolygon,
		Fee:       100,
		Height:    77770000,
		Hash:      "0x" + strings.Repeat("0", 64),
		CreatedAt: time.Now(),
	}, req)
	require.Nil(err)

	hash := "8375f2b2964b74c6313225887dc5e7f5006e04b0f5cd139342d01e54360d9900"
	rpc, _ := node.ethereumParams(common.SafeChainPolygon)
	tx, err := ethereum.RPCGetTransactionByHash(rpc, "0x"+hash)
	require.Nil(err)
	value, success := new(big.Int).SetString(tx.Value, 0)
	require.True(success)
	require.Equal(value.String(), "11000000000")
	amount := ethereum.NormallizeAmount(value, 18)
	require.Equal(amount.String(), "10000000000")

	output, err := testWriteOutput(ctx, db, node.conf.AppId, testEthereumBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromBigInt(amount, 1))
	require.Nil(err)
	action := &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testEthereumObserverHolderDeposit(ctx, require, node, hash, common.SafePolygonChainId, ethereum.EthereumEmptyAddress, amount.String())
}

func TestEthereumKeeper(t *testing.T) {
	require := require.New(t)
	ctx, node, db, _, signers := testEthereumPrepare(require)

	output, err := testWriteOutput(ctx, db, node.conf.AppId, testEthereumBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromInt(100000000000000))
	require.Nil(err)
	action := &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testEthereumObserverHolderDeposit(ctx, require, node, "ca6324635b0c87409e9d8488e7f6bcc1fd8224c276a3788b1a8c56ddb4e20f07", common.SafePolygonChainId, ethereum.EthereumEmptyAddress, "100000000000000")
	cnbAssetId := ethereum.GenerateAssetId(common.SafeChainPolygon, testEthereumUSDTAddress)
	require.Equal(testEthereumUSDTAssetId, cnbAssetId)
	cnbBondId := testDeployBondContract(ctx, require, node, testEthereumSafeAddress, cnbAssetId)
	require.Equal(testEthereumUSDTBondAssetId, cnbBondId)
	output, err = testWriteOutput(ctx, db, node.conf.AppId, testEthereumUSDTBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromInt(100000000000000))
	require.Nil(err)
	action = &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testEthereumObserverHolderDeposit(ctx, require, node, "55523d5ca29884f93dfa1c982177555ac5e13be49df10017054cb71aaba96595", cnbAssetId, testEthereumUSDTAddress, "100")

	balance, err := node.store.ReadEthereumBalance(ctx, testEthereumSafeAddress, common.SafePolygonChainId, testEthereumBondAssetId)
	require.Nil(err)
	require.Equal("0.0001", decimal.NewFromBigInt(balance.BigBalance(), -ethereum.ValuePrecision).String())
	balance, err = node.store.ReadEthereumBalance(ctx, testEthereumSafeAddress, testEthereumUSDTAssetId, testEthereumUSDTBondAssetId)
	require.Nil(err)
	require.Equal("0.0001", decimal.NewFromBigInt(balance.BigBalance(), -6).String())

	_, assetId := node.ethereumParams(common.SafeChainPolygon)
	txHash := testEthereumProposeTransaction(ctx, require, node, testEthereumBondAssetId, "3e37ea1c-1455-400d-9642-f6bbcd8c744e")
	testEthereumRevokeTransaction(ctx, require, node, txHash, false)
	txHash = testEthereumProposeTransaction(ctx, require, node, testEthereumBondAssetId, "3e37ea1c-1455-400d-9642-f6bbcd8c7441")
	testEthereumApproveTransaction(ctx, require, node, txHash, assetId, signers)
	balance, err = node.store.ReadEthereumBalance(ctx, testEthereumSafeAddress, common.SafePolygonChainId, testEthereumBondAssetId)
	require.Nil(err)
	require.Equal("0", decimal.NewFromBigInt(balance.BigBalance(), -ethereum.ValuePrecision).String())
	balance, err = node.store.ReadEthereumBalance(ctx, testEthereumSafeAddress, testEthereumUSDTAssetId, testEthereumUSDTBondAssetId)
	require.Nil(err)
	require.Equal("0.0001", decimal.NewFromBigInt(balance.BigBalance(), -6).String())

	for range 10 {
		testEthereumUpdateNetworkStatus(ctx, require, node, 80093737, "8c2120770291ddd4f5b632b429f1defa2745d5eb90e6e7d3bf2f6ce92e121559")
	}
	tx, err := node.store.ReadTransaction(ctx, txHash)
	require.Nil(err)
	safe, err := node.store.ReadSafe(ctx, tx.Holder)
	require.Nil(err)
	_, pubs := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	rpc, _ := node.ethereumParams(safe.Chain)
	chainId := ethereum.GetEvmChainID(common.SafeChainPolygon)
	nonce, err := ethereum.FetchSafeNonce(ctx, chainId, rpc, safe.Address, 80093737)
	require.Nil(err)
	require.Equal(int64(1), nonce)
	require.Equal(int64(2), safe.Nonce)

	rid := uuid.Must(uuid.NewV4()).String()
	holder := testPublicKey(testEthereumKeyHolder)
	info, err := node.store.ReadLatestNetworkInfo(ctx, common.SafeChainPolygon, time.Now())
	require.Nil(err)
	extra := []byte{common.FlagProposeCancelTransaction}
	extra = append(extra, uuid.Must(uuid.FromString(tx.RequestId)).Bytes()...)
	extra = append(extra, uuid.Must(uuid.FromString(info.RequestId)).Bytes()...)
	extra = append(extra, []byte(testEthereumTransactionReceiver)...)
	out := testBuildHolderRequest(node, rid, holder, common.ActionEthereumSafeProposeTransaction, testEthereumUSDTBondAssetId, extra, decimal.NewFromFloat(0.0001))
	testStep(ctx, require, node, out)
	b := testReadObserverResponse(ctx, require, node, rid, common.ActionEthereumSafeProposeTransaction)
	st, err := ethereum.UnmarshalSafeTransaction(b)
	require.Nil(err)
	require.Equal(int64(1), st.Nonce.Int64())
	stx, err := node.store.ReadTransaction(ctx, st.TxHash)
	require.Nil(err)
	require.Equal(hex.EncodeToString(st.Marshal()), stx.RawTransaction)
	require.Equal(common.RequestStateInitial, stx.State)

	for i, pub := range pubs {
		if pub == holder {
			sig := testEthereumSignMessage(require, testEthereumKeyHolder, st.Message)
			st.Signatures[i] = sig
		}
	}

	b = st.Marshal()
	ref := mc.Sha256Hash(b)
	err = node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(b))
	require.Nil(err)
	extra = uuid.Must(uuid.FromString(stx.RequestId)).Bytes()
	extra = append(extra, ref[:]...)
	id := uuid.Must(uuid.NewV4()).String()
	out = testBuildObserverRequest(node, id, testPublicKey(testEthereumKeyHolder), common.ActionEthereumSafeApproveTransaction, extra, common.CurveSecp256k1ECDSAPolygon)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, stx.TransactionHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, stx.TransactionHash)
	require.Equal(common.RequestStatePending, tx.State)
	msg, _ := hex.DecodeString(requests[0].Message)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignInput, msg, common.CurveSecp256k1ECDSAEthereum)
	op := signer.TestProcessOutput(ctx, require, signers, out, requests[0].RequestId)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignOutput, op.Extra, common.CurveSecp256k1ECDSAEthereum)
	testStep(ctx, require, node, out)

	safe, err = node.store.ReadSafe(ctx, tx.Holder)
	require.Nil(err)
	require.Equal(int64(2), safe.Nonce)
	balance, err = node.store.ReadEthereumBalance(ctx, testEthereumSafeAddress, common.SafePolygonChainId, testEthereumBondAssetId)
	require.Nil(err)
	require.Equal("0.0001", decimal.NewFromBigInt(balance.BigBalance(), -ethereum.ValuePrecision).String())
	balance, err = node.store.ReadEthereumBalance(ctx, testEthereumSafeAddress, testEthereumUSDTAssetId, testEthereumUSDTBondAssetId)
	require.Nil(err)
	require.Equal("0", decimal.NewFromBigInt(balance.BigBalance(), -6).String())
}

func TestEthereumKeeperERC20(t *testing.T) {
	require := require.New(t)
	ctx, node, db, _, signers := testEthereumPrepare(require)

	output, err := testWriteOutput(ctx, db, node.conf.AppId, testEthereumBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromInt(100000000000000))
	require.Nil(err)
	action := &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testEthereumObserverHolderDeposit(ctx, require, node, "ca6324635b0c87409e9d8488e7f6bcc1fd8224c276a3788b1a8c56ddb4e20f07", common.SafePolygonChainId, ethereum.EthereumEmptyAddress, "100000000000000")

	cnbAssetId := ethereum.GenerateAssetId(common.SafeChainPolygon, testEthereumUSDTAddress)
	require.Equal(testEthereumUSDTAssetId, cnbAssetId)
	cnbBondId := testDeployBondContract(ctx, require, node, testEthereumSafeAddress, cnbAssetId)
	require.Equal(testEthereumUSDTBondAssetId, cnbBondId)
	output, err = testWriteOutput(ctx, db, node.conf.AppId, testEthereumUSDTBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromInt(100000000000000))
	require.Nil(err)
	action = &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testEthereumObserverHolderDeposit(ctx, require, node, "55523d5ca29884f93dfa1c982177555ac5e13be49df10017054cb71aaba96595", cnbAssetId, testEthereumUSDTAddress, "100")

	txHash := testEthereumProposeERC20Transaction(ctx, require, node, testEthereumUSDTBondAssetId, "3e37ea1c-1455-400d-9642-f6bbcd8c7441")
	testEthereumApproveTransaction(ctx, require, node, txHash, cnbAssetId, signers)
}

func TestEthereumKeeperCloseAccountWithSignerObserver(t *testing.T) {
	require := require.New(t)
	ctx, node, db, _, signers := testEthereumPrepare(require)
	for range 10 {
		testEthereumUpdateNetworkStatus(ctx, require, node, 52430860, "55877f07c696cbf6e75174d7e8c2313d62aa665101be2c53dd1bd5f3a85507b1")
	}

	observer := testEthereumPublicKey(testEthereumKeyObserver)
	output, err := testWriteOutput(ctx, db, node.conf.AppId, testEthereumBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromInt(100000000000000))
	require.Nil(err)
	action := &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testEthereumObserverHolderDeposit(ctx, require, node, "ca6324635b0c87409e9d8488e7f6bcc1fd8224c276a3788b1a8c56ddb4e20f07", common.SafePolygonChainId, ethereum.EthereumEmptyAddress, "100000000000000")

	cnbAssetId := ethereum.GenerateAssetId(common.SafeChainPolygon, testEthereumUSDTAddress)
	require.Equal(testEthereumUSDTAssetId, cnbAssetId)
	cnbBondId := testDeployBondContract(ctx, require, node, testEthereumSafeAddress, cnbAssetId)
	require.Equal(testEthereumUSDTBondAssetId, cnbBondId)
	output, err = testWriteOutput(ctx, db, node.conf.AppId, testEthereumUSDTBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromInt(100000000000000))
	require.Nil(err)
	action = &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testEthereumObserverHolderDeposit(ctx, require, node, "55523d5ca29884f93dfa1c982177555ac5e13be49df10017054cb71aaba96595", cnbAssetId, testEthereumUSDTAddress, "100")

	txHash := testEthereumProposeRecoveryTransaction(ctx, require, node, cnbBondId, "3e37ea1c-1455-400d-9642-f6bbcd8c744e")
	id := uuid.Must(uuid.NewV4()).String()
	tx, _ := node.store.ReadTransaction(ctx, txHash)
	require.Equal(common.RequestStateInitial, tx.State)
	raw, _ := hex.DecodeString(tx.RawTransaction)
	st, err := ethereum.UnmarshalSafeTransaction(raw)
	require.Nil(err)

	safe, _ := node.store.ReadSafe(ctx, tx.Holder)
	_, pubs := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	for i, pub := range pubs {
		if pub == observer {
			sig := testEthereumSignMessage(require, testEthereumKeyObserver, st.Message)
			st.Signatures[i] = sig
		}
	}

	raw = st.Marshal()
	ref := mc.Sha256Hash(raw)
	err = node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(raw))
	require.Nil(err)
	extra := uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	extra = append(extra, ref[:]...)
	out := testBuildObserverRequest(node, id, tx.Holder, common.ActionEthereumSafeCloseAccount, extra, common.CurveSecp256k1ECDSAPolygon)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, tx.TransactionHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, tx.TransactionHash)
	require.Equal(common.RequestStatePending, tx.State)

	msg, _ := hex.DecodeString(requests[0].Message)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignInput, msg, common.CurveSecp256k1ECDSAEthereum)
	op := signer.TestProcessOutput(ctx, require, signers, out, requests[0].RequestId)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignOutput, op.Extra, common.CurveSecp256k1ECDSAEthereum)
	testStep(ctx, require, node, out)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, tx.TransactionHash, common.RequestStatePending)
	require.Len(requests, 0)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, tx.TransactionHash, common.RequestStateInitial)
	require.Len(requests, 0)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, tx.TransactionHash, common.RequestStateDone)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, tx.TransactionHash)
	require.Equal(common.RequestStateDone, tx.State)
	safe, err = node.store.ReadSafe(ctx, tx.Holder)
	require.Nil(err)
	require.Equal(common.RequestStateFailed, int(safe.State))

	mb := common.DecodeHexOrPanic(tx.RawTransaction)
	sTraceId := mc.Blake3Hash([]byte(common.Base91Encode(mb))).String()
	sTraceId = mtg.UniqueId(sTraceId, sTraceId)
	rid := common.UniqueId(tx.TransactionHash, sTraceId)
	b := testReadObserverResponse(ctx, require, node, rid, common.ActionEthereumSafeApproveTransaction)
	require.Equal(mb, b)

	_, assetId := node.ethereumParams(common.SafeChainPolygon)
	safeAssetId := node.getBondAssetId(ctx, node.conf.PolygonKeeperDepositEntry, assetId, safe.Holder)
	balance, err := node.store.ReadEthereumBalance(ctx, safe.Address, assetId, safeAssetId)
	require.Nil(err)
	require.Equal(int64(0), balance.BigBalance().Int64())

	safe, _ = node.store.ReadSafe(ctx, tx.Holder)
	require.Equal(int64(2), safe.Nonce)
}

func TestEthereumKeeperCloseAccountWithHolderObserver(t *testing.T) {
	require := require.New(t)
	ctx, node, db, _, _ := testEthereumPrepare(require)
	for range 10 {
		testEthereumUpdateNetworkStatus(ctx, require, node, 52430860, "55877f07c696cbf6e75174d7e8c2313d62aa665101be2c53dd1bd5f3a85507b1")
	}

	holder := testEthereumPublicKey(testEthereumKeyHolder)
	observer := testEthereumPublicKey(testEthereumKeyObserver)
	output, err := testWriteOutput(ctx, db, node.conf.AppId, testEthereumBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromInt(100000000000000))
	require.Nil(err)
	action := &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testEthereumObserverHolderDeposit(ctx, require, node, "ca6324635b0c87409e9d8488e7f6bcc1fd8224c276a3788b1a8c56ddb4e20f07", common.SafePolygonChainId, ethereum.EthereumEmptyAddress, "100000000000000")

	cnbAssetId := ethereum.GenerateAssetId(common.SafeChainPolygon, testEthereumUSDTAddress)
	require.Equal(testEthereumUSDTAssetId, cnbAssetId)
	cnbBondId := testDeployBondContract(ctx, require, node, testEthereumSafeAddress, cnbAssetId)
	require.Equal(testEthereumUSDTBondAssetId, cnbBondId)
	output, err = testWriteOutput(ctx, db, node.conf.AppId, testEthereumUSDTBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromInt(100000000000000))
	require.Nil(err)
	action = &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testEthereumObserverHolderDeposit(ctx, require, node, "55523d5ca29884f93dfa1c982177555ac5e13be49df10017054cb71aaba96595", cnbAssetId, testEthereumUSDTAddress, "100")

	safe, _ := node.store.ReadSafe(ctx, holder)
	chainId := ethereum.GetEvmChainID(common.SafeChainPolygon)
	id := common.UniqueId(testEthereumSafeAddress, testEthereumTransactionReceiver)

	safeBalances, err := node.store.ReadAllEthereumTokenBalances(ctx, safe.Address)
	require.Nil(err)
	var outputs []*ethereum.Output
	for _, b := range safeBalances {
		output := &ethereum.Output{
			Destination:  testEthereumTransactionReceiver,
			Amount:       b.BigBalance(),
			TokenAddress: b.AssetAddress,
		}
		outputs = append(outputs, output)
	}
	st, err := ethereum.CreateTransactionFromOutputs(ctx, ethereum.TypeMultiSendTx, chainId, id, testEthereumSafeAddress, outputs, big.NewInt(safe.Nonce))
	require.Nil(err)

	_, pubs := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	for i, pub := range pubs {
		if pub == observer {
			sig := testEthereumSignMessage(require, testEthereumKeyObserver, st.Message)
			st.Signatures[i] = sig
		}
		if pub == holder {
			sig := testEthereumSignMessage(require, testEthereumKeyHolder, st.Message)
			st.Signatures[i] = sig
		}
	}
	raw := st.Marshal()

	ref := mc.Sha256Hash(raw)
	err = node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(raw))
	require.Nil(err)
	extra := uuid.Nil.Bytes()
	extra = append(extra, ref[:]...)
	id = uuid.Must(uuid.NewV4()).String()
	out := testBuildObserverRequest(node, id, holder, common.ActionEthereumSafeCloseAccount, extra, common.CurveSecp256k1ECDSAPolygon)
	testStep(ctx, require, node, out)

	stx := node.buildStorageTransaction(ctx, &common.Request{Sequence: sequence, Output: action}, []byte(common.Base91Encode(raw)))
	require.NotNil(stx)
	rid := common.UniqueId(st.TxHash, stx.TraceId)
	b := testReadObserverResponse(ctx, require, node, rid, common.ActionEthereumSafeApproveTransaction)
	require.Equal(b, raw)

	tx, err := node.store.ReadTransaction(ctx, st.TxHash)
	require.Nil(err)
	require.Equal(common.RequestStateDone, tx.State)
	safe, err = node.store.ReadSafe(ctx, tx.Holder)
	require.Nil(err)
	require.Equal(common.RequestStateFailed, int(safe.State))
}

func TestEthereumKeeperSetInheritanceLocks(t *testing.T) {
	require := require.New(t)
	ctx, node, db, _, signers := testEthereumPrepare(require)
	for range 10 {
		testEthereumUpdateNetworkStatus(ctx, require, node, 78621270, "969a55ec9598bd6c5308da6adf6362c7b6521a1965a9ef0f14daae7a67e939de")
	}

	holder := testEthereumPublicKey(testEthereumKeyHolder)
	output, err := testWriteOutput(ctx, db, node.conf.AppId, testEthereumBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromInt(100000000000000))
	require.Nil(err)
	action := &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testEthereumObserverHolderDeposit(ctx, require, node, "ca6324635b0c87409e9d8488e7f6bcc1fd8224c276a3788b1a8c56ddb4e20f07", common.SafePolygonChainId, ethereum.EthereumEmptyAddress, "100000000000000")
	testEthereumObserverHolderDeposit(ctx, require, node, "bf84a0728f43681078ffa9f3507125b7bd90e4afbefed99c6006f31a1172230f", common.SafePolygonChainId, ethereum.EthereumEmptyAddress, "1000000000000000000")

	cnbAssetId := ethereum.GenerateAssetId(common.SafeChainPolygon, testEthereumUSDTAddress)
	require.Equal(testEthereumUSDTAssetId, cnbAssetId)
	cnbBondId := testDeployBondContract(ctx, require, node, testEthereumSafeAddress, cnbAssetId)
	require.Equal(testEthereumUSDTBondAssetId, cnbBondId)
	output, err = testWriteOutput(ctx, db, node.conf.AppId, testEthereumUSDTBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromInt(100000000000000))
	require.Nil(err)
	action = &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testEthereumObserverHolderDeposit(ctx, require, node, "55523d5ca29884f93dfa1c982177555ac5e13be49df10017054cb71aaba96595", cnbAssetId, testEthereumUSDTAddress, "100")

	safe, _ := node.store.ReadSafe(ctx, holder)
	require.Equal(safe.Timelock, time.Hour)
	require.Equal(common.RequestStateDone, int(safe.State))

	safeBalances, err := node.store.ReadAllEthereumTokenBalances(ctx, safe.Address)
	require.Nil(err)
	for _, b := range safeBalances {
		switch b.AssetId {
		case common.SafePolygonChainId:
			require.Equal(int64(1000100000000000000), b.BigBalance().Int64())
		case testEthereumUSDTBondAssetId:
			require.Equal(100, b.BigBalance().Int64())
		}
	}

	// create but revoke
	rid := "358c0e9e-8d9c-4e0f-acde-8945a859763b"
	transactionHash := testEthereumSafeSetInheritanceLock(ctx, require, node, "", 10, cnbBondId, rid, "a80ccea20369f978cac1d7a5f610c5e5fc643989a90be484c625b53c767857bf", "00000000000000890000000000000000004061383063636561323033363966393738636163316437613566363130633565356663363433393839613930626534383463363235623533633736373835376266002a3078333436363037656231353832314134453139343632383434344633373035633236433845366542650014c2132d05d31c914a87c6611c10748aeb04b58e8f00000044a9059cbb000000000000000000000000a03a8590bb3a2ca5c747c8b99c63da399424a0550000000000000000000000000000000000000000000000000000000000000064000101002045fca74a7dc95b2b94e78e39477dc900f6b4d10fcbca5e45d49ee85fdb5ab2df00022c2c")
	l, err := node.store.ReadLatestInheritanceLockByHolder(ctx, holder)
	require.Nil(err)
	require.Equal(l.RequestId, rid)
	require.Equal(l.State, byte(common.RequestStateInitial))
	testEthereumRevokeTransaction(ctx, require, node, transactionHash, false)
	l, err = node.store.ReadLatestInheritanceLockByHolder(ctx, holder)
	require.Nil(err)
	require.Equal(l.State, byte(common.RequestStateFailed))

	// create
	rid = "358c0e9e-8d9c-4e0f-acde-8945a859763a"
	transactionHash = testEthereumSafeSetInheritanceLock(ctx, require, node, "", 10, cnbBondId, rid, "5137b99216af5c2c42438dfba493eab4b28c73decdc140068a5a8f136c8c0c08", "00000000000000890000000000000000004035313337623939323136616635633263343234333864666261343933656162346232386337336465636463313430303638613561386631333663386330633038002a3078333436363037656231353832314134453139343632383434344633373035633236433845366542650014c2132d05d31c914a87c6611c10748aeb04b58e8f00000044a9059cbb000000000000000000000000a03a8590bb3a2ca5c747c8b99c63da399424a0550000000000000000000000000000000000000000000000000000000000000064000101002045fca74a7dc95b2b94e78e39477dc900f6b4d10fcbca5e45d49ee85fdb5ab2df00022c2c")
	testEthereumSafeApproveLockTransaction(ctx, require, node, transactionHash, signers)
	l, err = node.store.ReadLatestInheritanceLockByHolder(ctx, holder)
	require.Nil(err)
	require.Equal(l.RequestId, "358c0e9e-8d9c-4e0f-acde-8945a859763a")
	l, err = node.store.ReadInheritanceLockByRequestId(ctx, "358c0e9e-8d9c-4e0f-acde-8945a859763a")
	require.Nil(err)
	require.Equal(l.Duration, 10*time.Hour)
	require.Equal(l.Hash, mc.Sha256Hash([]byte{common.FlagProposeSetInheritance, byte(10)}).String())
	require.Equal(int(l.State), common.RequestStateDone)
	ls, err := node.store.ListInheritanceLocksByHolder(ctx, holder)
	require.Nil(err)
	require.Len(ls, 2)

	// update but revoke
	rid = "1924a324-dbcb-48db-b0ea-5d23ebe59474"
	transactionHash = testEthereumSafeSetInheritanceLock(ctx, require, node, "", 20, testEthereumBondAssetId, rid, "016b8f8e219d3c38bcc1582ab18e6403df1509c9afb0c838829f3585d3281681", "00000000000000890000000000000000004030313662386638653231396433633338626363313538326162313865363430336466313530396339616662306338333838323966333538356433323831363831002a3078333436363037656231353832314134453139343632383434344633373035633236433845366542650014a03a8590bb3a2ca5c747c8b99c63da399424a05500065af3107a40000000000102002047a466f99f9e418aa3ea44259b13841354e0c7eed32e6ab33b7a1ac5d5abb1a700022c2c")
	l, err = node.store.ReadLatestInheritanceLockByHolder(ctx, holder)
	require.Nil(err)
	require.Equal(l.RequestId, rid)
	require.Equal(l.State, byte(common.RequestStateInitial))
	testEthereumRevokeTransaction(ctx, require, node, transactionHash, false)
	l, err = node.store.ReadLatestInheritanceLockByHolder(ctx, holder)
	require.Nil(err)
	require.Equal(l.State, byte(common.RequestStateFailed))

	// update
	rid = "1924a324-dbcb-48db-b0ea-5d23ebe59475"
	transactionHash = testEthereumSafeSetInheritanceLock(ctx, require, node, "", 20, testEthereumBondAssetId, rid, "d78266795f625c785433617c932ed7d2d9ffc0b6b1dc83582a0f9ece8afb7bef", "00000000000000890000000000000000004064373832363637393566363235633738353433333631376339333265643764326439666663306236623164633833353832613066396563653861666237626566002a3078333436363037656231353832314134453139343632383434344633373035633236433845366542650014a03a8590bb3a2ca5c747c8b99c63da399424a05500065af3107a40000000000102002047a466f99f9e418aa3ea44259b13841354e0c7eed32e6ab33b7a1ac5d5abb1a700022c2c")
	testEthereumSafeApproveLockTransaction(ctx, require, node, transactionHash, signers)
	l, err = node.store.ReadInheritanceLockByRequestId(ctx, "358c0e9e-8d9c-4e0f-acde-8945a859763a")
	require.Nil(err)
	require.Equal(int(l.State), common.RequestStateFailed)
	l, err = node.store.ReadLatestInheritanceLockByHolder(ctx, holder)
	require.Nil(err)
	require.Equal(l.RequestId, "1924a324-dbcb-48db-b0ea-5d23ebe59475")
	l, err = node.store.ReadInheritanceLockByRequestId(ctx, "1924a324-dbcb-48db-b0ea-5d23ebe59475")
	require.Nil(err)
	require.Equal(l.Duration, 20*time.Hour)
	require.Equal(l.Hash, mc.Sha256Hash([]byte{common.FlagProposeSetInheritance, byte(20)}).String())
	require.Equal(int(l.State), common.RequestStateDone)
	ls, err = node.store.ListInheritanceLocksByHolder(ctx, holder)
	require.Nil(err)
	require.Len(ls, 4)

	// remove but revoke
	transactionHash = testEthereumSafeSetInheritanceLock(ctx, require, node, l.LockId, 20, testEthereumBondAssetId, "1924a324-dbcb-48db-b0ea-5d23ebe59470", "d8ab2dfda43659a75a5456e7332dbf58ff1e9677702d8c3094f46e5cef6ee2fe", "00000000000000890000000000000000004064386162326466646134333635396137356135343536653733333264626635386666316539363737373032643863333039346634366535636566366565326665002a3078333436363037656231353832314134453139343632383434344633373035633236433845366542650014a03a8590bb3a2ca5c747c8b99c63da399424a05500065af3107a4000000000010300209ff24b9847958aacac35ee9d7561734ba466c016795f247e64f933c396facdc400022c2c")
	l, err = node.store.ReadLatestInheritanceLockByHolder(ctx, holder)
	require.Nil(err)
	require.Equal(l.RequestId, rid)
	require.Equal(l.State, byte(common.RequestStateDone))
	testEthereumRevokeTransaction(ctx, require, node, transactionHash, false)
	l, err = node.store.ReadLatestInheritanceLockByHolder(ctx, holder)
	require.Nil(err)
	require.Equal(l.State, byte(common.RequestStateDone))

	// remove
	transactionHash = testEthereumSafeSetInheritanceLock(ctx, require, node, l.LockId, 20, testEthereumBondAssetId, "1924a324-dbcb-48db-b0ea-5d23ebe59471", "d36c44b4ceebe792e05a385ee245d420c6082b5e4fb0c55f6d4b61e181c0e1ca", "00000000000000890000000000000000004064333663343462346365656265373932653035613338356565323435643432306336303832623565346662306335356636643462363165313831633065316361002a3078333436363037656231353832314134453139343632383434344633373035633236433845366542650014a03a8590bb3a2ca5c747c8b99c63da399424a05500065af3107a4000000000010300209ff24b9847958aacac35ee9d7561734ba466c016795f247e64f933c396facdc400022c2c")
	testEthereumSafeApproveLockTransaction(ctx, require, node, transactionHash, signers)
	l, err = node.store.ReadLatestInheritanceLockByHolder(ctx, holder)
	require.Nil(err)
	require.Equal(l.RequestId, "1924a324-dbcb-48db-b0ea-5d23ebe59475")
	l, err = node.store.ReadInheritanceLockByRequestId(ctx, "1924a324-dbcb-48db-b0ea-5d23ebe59475")
	require.Nil(err)
	require.Equal(int(l.State), common.RequestStateFailed)
	ls, err = node.store.ListInheritanceLocksByHolder(ctx, holder)
	require.Nil(err)
	require.Len(ls, 4)
	for _, l := range ls {
		require.Equal(int(l.State), common.RequestStateFailed)
	}
}

func TestEthereumKeeperCloseAccountByInheritanceWithSignerObserver(t *testing.T) {
	require := require.New(t)
	ctx, node, db, _, signers := testEthereumPrepare(require)

	holder := testEthereumPublicKey(testEthereumKeyHolder)
	observer := testEthereumPublicKey(testEthereumKeyObserver)
	output, err := testWriteOutput(ctx, db, node.conf.AppId, testEthereumBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromInt(100000000000000))
	require.Nil(err)
	action := &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testEthereumObserverHolderDeposit(ctx, require, node, "ca6324635b0c87409e9d8488e7f6bcc1fd8224c276a3788b1a8c56ddb4e20f07", common.SafePolygonChainId, ethereum.EthereumEmptyAddress, "100000000000000")

	cnbAssetId := ethereum.GenerateAssetId(common.SafeChainPolygon, testEthereumUSDTAddress)
	require.Equal(testEthereumUSDTAssetId, cnbAssetId)
	cnbBondId := testDeployBondContract(ctx, require, node, testEthereumSafeAddress, cnbAssetId)
	require.Equal(testEthereumUSDTBondAssetId, cnbBondId)
	output, err = testWriteOutput(ctx, db, node.conf.AppId, testEthereumUSDTBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromInt(100000000000000))
	require.Nil(err)
	action = &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testEthereumObserverHolderDeposit(ctx, require, node, "55523d5ca29884f93dfa1c982177555ac5e13be49df10017054cb71aaba96595", cnbAssetId, testEthereumUSDTAddress, "100")

	safe, _ := node.store.ReadSafe(ctx, holder)
	require.Equal(safe.Timelock, time.Hour)
	require.Equal(common.RequestStateDone, int(safe.State))
	require.Equal(safe.Timelock, time.Hour)

	transactionHash := testEthereumSafeSetInheritanceLock(ctx, require, node, "", 10, cnbBondId, "358c0e9e-8d9c-4e0f-acde-8945a859763a", "5137b99216af5c2c42438dfba493eab4b28c73decdc140068a5a8f136c8c0c08", "00000000000000890000000000000000004035313337623939323136616635633263343234333864666261343933656162346232386337336465636463313430303638613561386631333663386330633038002a3078333436363037656231353832314134453139343632383434344633373035633236433845366542650014c2132d05d31c914a87c6611c10748aeb04b58e8f00000044a9059cbb000000000000000000000000a03a8590bb3a2ca5c747c8b99c63da399424a0550000000000000000000000000000000000000000000000000000000000000064000101002045fca74a7dc95b2b94e78e39477dc900f6b4d10fcbca5e45d49ee85fdb5ab2df00022c2c")
	testEthereumSafeApproveLockTransaction(ctx, require, node, transactionHash, signers)
	l, err := node.store.ReadLatestInheritanceLockByHolder(ctx, holder)
	require.Nil(err)
	require.Equal(l.RequestId, "358c0e9e-8d9c-4e0f-acde-8945a859763a")
	l, err = node.store.ReadInheritanceLockByRequestId(ctx, "358c0e9e-8d9c-4e0f-acde-8945a859763a")
	require.Nil(err)
	require.Equal(l.Duration, 10*time.Hour)
	require.Equal(l.Hash, mc.Sha256Hash([]byte{common.FlagProposeSetInheritance, byte(10)}).String())
	require.Equal(int(l.State), common.RequestStateDone)

	for range 10 {
		testEthereumUpdateNetworkStatus(ctx, require, node, 78621270, "969a55ec9598bd6c5308da6adf6362c7b6521a1965a9ef0f14daae7a67e939de")
	}

	safeBalances, err := node.store.ReadAllEthereumTokenBalances(ctx, safe.Address)
	require.Nil(err)
	var outputs []*ethereum.Output
	for _, b := range safeBalances {
		if b.BigBalance().Sign() == 0 {
			continue
		}
		output := &ethereum.Output{
			Destination:  testEthereumTransactionReceiver,
			Amount:       b.BigBalance(),
			TokenAddress: b.AssetAddress,
		}
		outputs = append(outputs, output)
	}
	txType := ethereum.TypeETHTx
	switch {
	case len(outputs) > 1:
		txType = ethereum.TypeMultiSendTx
	case outputs[0].TokenAddress != ethereum.EthereumEmptyAddress:
		txType = ethereum.TypeERC20Tx
	}
	id := uuid.Must(uuid.NewV4())
	st, err := ethereum.CreateTransactionFromOutputs(ctx, txType, ethereum.GetEvmChainID(common.SafeChainPolygon), id.String(), testEthereumSafeAddress, outputs, big.NewInt(safe.Nonce))
	require.Nil(err)
	_, pubs := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	for i, pub := range pubs {
		if pub == observer {
			sig := testEthereumSignMessage(require, testEthereumKeyObserver, st.Message)
			st.Signatures[i] = sig
		}
		if pub == holder {
			sig := testEthereumSignMessage(require, testEthereumKeyHolder, st.Message)
			st.Signatures[i] = sig
		}
	}
	raw := st.Marshal()
	ref := mc.Sha256Hash(raw)
	err = node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(raw))
	require.Nil(err)
	out := testBuildObserverRequest(node, id.String(), holder, common.ActionEthereumSafeCloseAccountByInheritance, ref[:], common.CurveSecp256k1ECDSAPolygon)
	testStep(ctx, require, node, out)

	tx, err := node.store.ReadTransaction(ctx, st.TxHash)
	require.Nil(err)
	require.Equal(common.RequestStateDone, tx.State)
	safe, err = node.store.ReadSafe(ctx, holder)
	require.Nil(err)
	require.Equal(common.RequestStateFailed, int(safe.State))

}

func testEthereumPrepare(require *require.Assertions) (context.Context, *Node, *mtg.SQLite3Store, string, []*signer.Node) {
	logger.SetLevel(logger.INFO)
	ctx, signers, _ := signer.TestPrepare(require)
	mpc, cc := signer.TestCMPPrepareKeys(ctx, require, signers, common.CurveSecp256k1ECDSAEthereum)
	chainCode := common.DecodeHexOrPanic(cc)

	root, err := os.MkdirTemp("", "safe-keeper-test-")
	require.Nil(err)
	node, db := testBuildNode(ctx, require, root)
	require.NotNil(node)
	timestamp, err := node.timestamp(ctx)
	require.Nil(err)
	require.Equal(node.conf.MTG.Genesis.Epoch, timestamp)
	testSpareKeys(ctx, require, node, 0, 0, 0, common.CurveSecp256k1ECDSAEthereum)

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
	observer := testEthereumPublicKey(testEthereumKeyObserver)
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
	dummy := testEthereumPublicKey(testEthereumKeyHolder)
	out = testBuildObserverRequest(node, id, dummy, common.ActionObserverRequestSignerKeys, []byte{batch}, common.CurveSecp256k1ECDSAEthereum)
	testStep(ctx, require, node, out)
	signerMembers := node.GetSigners()
	for i := range batch {
		pid := common.UniqueId(id, fmt.Sprintf("%8d", i))
		pid = common.UniqueId(pid, fmt.Sprintf("MTG:%v:%d", signerMembers, node.signer.Genesis.Threshold))
		v, _ := node.store.ReadProperty(ctx, pid)
		var om map[string]any
		err = json.Unmarshal([]byte(v), &om)
		require.Nil(err)
		b, _ := hex.DecodeString(om["memo"].(string))
		b = common.AESDecrypt(node.signerAESKey[:], b)
		o, err := common.DecodeOperation(b)
		require.Nil(err)
		require.Equal(pid, o.Id)
	}
	testSpareKeys(ctx, require, node, 0, 1, 1, common.CurveSecp256k1ECDSAEthereum)

	for range 10 {
		testEthereumUpdateAccountPrice(ctx, require, node)
	}
	rid, gs := testEthereumProposeAccount(ctx, require, node, mpc, observer)
	testSpareKeys(ctx, require, node, 0, 0, 0, common.CurveSecp256k1ECDSAEthereum)
	testEthereumApproveAccount(ctx, require, node, rid, gs, signers, mpc, observer)
	testSpareKeys(ctx, require, node, 0, 0, 0, common.CurveSecp256k1ECDSAEthereum)
	for range 10 {
		testEthereumUpdateNetworkStatus(ctx, require, node, 52430860, "55877f07c696cbf6e75174d7e8c2313d62aa665101be2c53dd1bd5f3a85507b1")
	}

	holder := testEthereumPublicKey(testEthereumKeyHolder)
	safe, _ := node.store.ReadSafe(ctx, holder)
	require.Equal(int64(1), safe.Nonce)
	return ctx, node, db, mpc, signers
}

func testEthereumSafeSetInheritanceLock(ctx context.Context, require *require.Assertions, node *Node, removeId string, lock int, bondId string, rid, rhash, rraw string) string {
	flag := byte(common.FlagProposeSetInheritance)
	if removeId != "" {
		flag = common.FlagProposeRemoveInheritance
	}

	holder := testPublicKey(testEthereumKeyHolder)
	hash := mc.Sha256Hash([]byte{flag, byte(lock)})

	info, _ := node.store.ReadLatestNetworkInfo(ctx, common.SafeChainPolygon, time.Now())
	extra := []byte{flag}
	if flag == common.FlagProposeRemoveInheritance {
		extra = append(extra, uuid.FromStringOrNil(removeId).Bytes()...)
	} else {
		extra = append(extra, hash[:]...)
		extra = append(extra, binary.BigEndian.AppendUint16(nil, uint16(lock))...)
	}
	extra = append(extra, uuid.Must(uuid.FromString(info.RequestId)).Bytes()...)
	extra = append(extra, []byte(testEthereumTransactionReceiver)...)
	out := testBuildHolderRequest(node, rid, holder, common.ActionEthereumSafeProposeTransaction, bondId, extra, decimal.NewFromFloat(0.0001))
	testStep(ctx, require, node, out)

	b := testReadObserverResponse(ctx, require, node, rid, common.ActionEthereumSafeProposeTransaction)
	t, err := ethereum.UnmarshalSafeTransaction(b)
	require.Nil(err)
	require.Equal(rhash, t.TxHash)
	require.Equal(rraw, hex.EncodeToString(b))

	amt := decimal.NewFromBigInt(t.Value, -ethereum.ValuePrecision)
	if bondId == testEthereumBondAssetId {
		require.Equal(testEthereumTransactionReceiver, t.Destination.Hex())
		require.Equal("0.0001", amt.String())
	} else {
		require.Equal(testEthereumUSDTAddress, t.Destination.Hex())
		require.Equal("0", amt.String())
	}
	require.Equal(testEthereumSafeAddress, t.SafeAddress)

	stx, err := node.store.ReadTransaction(ctx, t.TxHash)
	require.Nil(err)
	require.Equal(hex.EncodeToString(t.Marshal()), stx.RawTransaction)
	require.Equal(common.RequestStateInitial, stx.State)

	return stx.TransactionHash
}

func testEthereumSafeApproveLockTransaction(ctx context.Context, require *require.Assertions, node *Node, transactionHash string, signers []*signer.Node) {
	id := uuid.Must(uuid.NewV4()).String()

	tx, _ := node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateInitial, tx.State)
	raw, err := hex.DecodeString(tx.RawTransaction)
	require.Nil(err)
	t, err := ethereum.UnmarshalSafeTransaction(raw)
	require.Nil(err)

	safe, _ := node.store.ReadSafe(ctx, tx.Holder)
	_, pubs := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)

	holder := testEthereumPublicKey(testEthereumKeyHolder)
	for i, pub := range pubs {
		if pub == holder {
			sig := testEthereumSignMessage(require, testEthereumKeyHolder, t.Message)
			t.Signatures[i] = sig
		}
	}

	raw = t.Marshal()
	ref := mc.Sha256Hash(raw)
	err = node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(raw))
	require.Nil(err)
	extra := uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	extra = append(extra, ref[:]...)

	out := testBuildObserverRequest(node, id, testPublicKey(testEthereumKeyHolder), common.ActionEthereumSafeApproveTransaction, extra, common.CurveSecp256k1ECDSAPolygon)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStatePending, tx.State)

	msg, _ := hex.DecodeString(requests[0].Message)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignInput, msg, common.CurveSecp256k1ECDSAEthereum)
	op := signer.TestProcessOutput(ctx, require, signers, out, requests[0].RequestId)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignOutput, op.Extra, common.CurveSecp256k1ECDSAEthereum)
	testStep(ctx, require, node, out)

	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateDone, tx.State)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Len(requests, 0)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStatePending)
	require.Len(requests, 0)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateDone)
	require.Len(requests, 1)
}

func testEthereumProposeTransaction(ctx context.Context, require *require.Assertions, node *Node, bondId string, rid string) string {
	holder := testPublicKey(testEthereumKeyHolder)
	info, err := node.store.ReadLatestNetworkInfo(ctx, common.SafeChainPolygon, time.Now())
	require.Nil(err)
	extra := []byte{0}
	extra = append(extra, uuid.Must(uuid.FromString(info.RequestId)).Bytes()...)
	extra = append(extra, []byte(testEthereumTransactionReceiver)...)
	out := testBuildHolderRequest(node, rid, holder, common.ActionEthereumSafeProposeTransaction, bondId, extra, decimal.NewFromFloat(0.0001))
	testStep(ctx, require, node, out)

	b := testReadObserverResponse(ctx, require, node, rid, common.ActionEthereumSafeProposeTransaction)
	t, err := ethereum.UnmarshalSafeTransaction(b)
	require.Nil(err)

	amt := decimal.NewFromBigInt(t.Value, -ethereum.ValuePrecision)
	require.Equal("0.0001", amt.String())
	require.Equal(testEthereumTransactionReceiver, t.Destination.Hex())
	require.Equal(testEthereumSafeAddress, t.SafeAddress)

	stx, err := node.store.ReadTransaction(ctx, t.TxHash)
	require.Nil(err)
	require.Equal(hex.EncodeToString(t.Marshal()), stx.RawTransaction)
	require.Equal("[{\"amount\":\"0.0001\",\"receiver\":\"0xA03A8590BB3A2cA5c747c8b99C63DA399424a055\"}]", stx.Data)
	require.Equal(common.RequestStateInitial, stx.State)

	return stx.TransactionHash
}

func testEthereumProposeERC20Transaction(ctx context.Context, require *require.Assertions, node *Node, bondId string, rid string) string {
	holder := testPublicKey(testEthereumKeyHolder)
	info, err := node.store.ReadLatestNetworkInfo(ctx, common.SafeChainPolygon, time.Now())
	require.Nil(err)
	extra := []byte{0}
	extra = append(extra, uuid.Must(uuid.FromString(info.RequestId)).Bytes()...)
	extra = append(extra, []byte(testEthereumTransactionReceiver)...)
	out := testBuildHolderRequest(node, rid, holder, common.ActionEthereumSafeProposeTransaction, bondId, extra, decimal.NewFromFloat(0.0001))
	testStep(ctx, require, node, out)

	b := testReadObserverResponse(ctx, require, node, rid, common.ActionEthereumSafeProposeTransaction)
	t, err := ethereum.UnmarshalSafeTransaction(b)
	require.Nil(err)
	require.Equal(int64(0), t.Value.Int64())
	require.Equal(testEthereumUSDTAddress, t.Destination.Hex())
	require.Equal(testEthereumSafeAddress, t.SafeAddress)

	stx, err := node.store.ReadTransaction(ctx, t.TxHash)
	require.Nil(err)
	require.Equal(hex.EncodeToString(t.Marshal()), stx.RawTransaction)
	require.Equal(common.RequestStateInitial, stx.State)
	return stx.TransactionHash
}

func testEthereumProposeRecoveryTransaction(ctx context.Context, require *require.Assertions, node *Node, bondId string, rid string) string {
	holder := testPublicKey(testEthereumKeyHolder)
	info, err := node.store.ReadLatestNetworkInfo(ctx, common.SafeChainPolygon, time.Now())
	require.Nil(err)
	extra := []byte{1}
	extra = append(extra, uuid.Must(uuid.FromString(info.RequestId)).Bytes()...)
	extra = append(extra, []byte(testEthereumTransactionReceiver)...)
	out := testBuildHolderRequest(node, rid, holder, common.ActionEthereumSafeProposeTransaction, bondId, extra, decimal.NewFromFloat(0.0001))
	testStep(ctx, require, node, out)

	b := testReadObserverResponse(ctx, require, node, rid, common.ActionEthereumSafeProposeTransaction)
	t, err := ethereum.UnmarshalSafeTransaction(b)
	require.Nil(err)
	require.Equal(int64(0), t.Value.Int64())
	require.Equal(ethereum.EthereumMultiSendAddress, t.Destination.Hex())
	require.Equal(testEthereumSafeAddress, t.SafeAddress)

	stx, err := node.store.ReadTransaction(ctx, t.TxHash)
	require.Nil(err)
	require.Equal(hex.EncodeToString(t.Marshal()), stx.RawTransaction)
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
	sig := testEthereumSignMessage(require, key, []byte(ms))

	extra := uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	extra = append(extra, sig...)

	out := testBuildObserverRequest(node, id, testPublicKey(testEthereumKeyHolder), common.ActionEthereumSafeRevokeTransaction, extra, common.CurveSecp256k1ECDSAPolygon)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 0)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateFailed, tx.State)
}

func testEthereumApproveTransaction(ctx context.Context, require *require.Assertions, node *Node, transactionHash, assetId string, signers []*signer.Node) {
	id := uuid.Must(uuid.NewV4()).String()

	tx, _ := node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateInitial, tx.State)
	raw, err := hex.DecodeString(tx.RawTransaction)
	require.Nil(err)
	t, err := ethereum.UnmarshalSafeTransaction(raw)
	require.Nil(err)

	safe, _ := node.store.ReadSafe(ctx, tx.Holder)
	_, pubs := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)

	holder := testEthereumPublicKey(testEthereumKeyHolder)
	for i, pub := range pubs {
		if pub == holder {
			sig := testEthereumSignMessage(require, testEthereumKeyHolder, t.Message)
			t.Signatures[i] = sig
		}
	}

	raw = t.Marshal()
	ref := mc.Sha256Hash(raw)
	err = node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(raw))
	require.Nil(err)
	extra := uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	extra = append(extra, ref[:]...)

	out := testBuildObserverRequest(node, id, testPublicKey(testEthereumKeyHolder), common.ActionEthereumSafeApproveTransaction, extra, common.CurveSecp256k1ECDSAPolygon)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStatePending, tx.State)

	msg, _ := hex.DecodeString(requests[0].Message)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignInput, msg, common.CurveSecp256k1ECDSAEthereum)
	op := signer.TestProcessOutput(ctx, require, signers, out, requests[0].RequestId)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignOutput, op.Extra, common.CurveSecp256k1ECDSAEthereum)
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

	safeAssetId := node.getBondAssetId(ctx, node.conf.PolygonKeeperDepositEntry, assetId, holder)
	balance, err := node.store.ReadEthereumBalance(ctx, safe.Address, assetId, safeAssetId)
	require.Nil(err)
	require.Equal(int64(0), balance.BigBalance().Int64())

	safe, _ = node.store.ReadSafe(ctx, tx.Holder)
	require.Equal(int64(2), safe.Nonce)
}

func testEthereumProposeAccount(ctx context.Context, require *require.Assertions, node *Node, signer, observer string) (string, *ethereum.GnosisSafe) {
	id := uuid.Must(uuid.NewV4()).String()
	holder := testEthereumPublicKey(testEthereumKeyHolder)
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

	owners, _ := ethereum.GetSortedSafeOwners(holder, signer, observer)
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
	holder := testEthereumPublicKey(testEthereumKeyHolder)
	sp, err := node.store.ReadSafeProposalByAddress(ctx, gs.Address)
	require.Nil(err)

	tx, err := node.store.ReadTransaction(ctx, gs.TxHash)
	require.Nil(err)
	raw, err := hex.DecodeString(tx.RawTransaction)
	require.Nil(err)
	t, err := ethereum.UnmarshalSafeTransaction(raw)
	require.Nil(err)
	outputs, err := t.ExtractOutputs()
	require.NotNil(err)
	require.Len(outputs, 0)
	signature := testEthereumSignMessage(require, testEthereumKeyHolder, t.Message)

	extra := uuid.FromStringOrNil(rid).Bytes()
	extra = append(extra, signature[:]...)
	out := testBuildObserverRequest(node, approveRequestId, holder, common.ActionEthereumSafeApproveAccount, extra, common.CurveSecp256k1ECDSAPolygon)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, gs.TxHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, gs.TxHash)
	require.Equal(common.RequestStatePending, tx.State)

	msg, _ := hex.DecodeString(requests[0].Message)
	out = testBuildSignerOutput(node, requests[0].RequestId, sp.Signer, common.OperationTypeSignInput, msg, common.CurveSecp256k1ECDSAEthereum)
	op := signer.TestProcessOutput(ctx, require, signers, out, requests[0].RequestId)
	out = testBuildSignerOutput(node, requests[0].RequestId, sp.Signer, common.OperationTypeSignOutput, op.Extra, common.CurveSecp256k1ECDSAEthereum)
	testStep(ctx, require, node, out)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, gs.TxHash, common.RequestStateDone)
	require.Len(requests, 1)

	id := common.UniqueId(requests[0].RequestId, gs.Address)
	r := testReadObserverResponse(ctx, require, node, id, common.ActionEthereumSafeApproveAccount)
	gs, err = ethereum.UnmarshalGnosisSafe(r)
	require.Nil(err)
	require.Equal(testEthereumSafeAddress, gs.Address)
	tx, _ = node.store.ReadTransaction(ctx, gs.TxHash)
	require.Equal(common.RequestStateDone, tx.State)

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

	bondId := testDeployBondContract(ctx, require, node, testEthereumSafeAddress, common.SafePolygonChainId)
	require.Equal(testEthereumBondAssetId, bondId)

	owners, pubs := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	rpc, _ := node.ethereumParams(safe.Chain)
	raw, err = hex.DecodeString(tx.RawTransaction)
	require.Nil(err)
	t, err = ethereum.UnmarshalSafeTransaction(raw)
	require.Nil(err)
	var index int64
	for i, pub := range pubs {
		if pub == safe.Observer {
			index = int64(i)
		}
	}
	chainId := ethereum.GetEvmChainID(int64(safe.Chain))
	safeAddress, err := ethereum.GetOrDeploySafeAccount(ctx, rpc, os.Getenv("MVM_DEPLOYER"), chainId, owners, 2, int64(safe.Timelock/time.Hour), index, t)
	require.Nil(err)
	require.Equal(testEthereumSafeAddress, safeAddress.Hex())
}

func testEthereumObserverHolderDeposit(ctx context.Context, require *require.Assertions, node *Node, txHash, assetId, assetAddress, amount string) {
	id := uuid.Must(uuid.NewV4()).String()
	amt := decimal.RequireFromString(amount)
	b, err := hex.DecodeString(txHash)
	require.Nil(err)

	rpc, _ := node.ethereumParams(common.SafeChainPolygon)
	if !strings.HasPrefix(txHash, "0x") {
		txHash = "0x" + txHash
	}
	etx, err := ethereum.RPCGetTransactionByHash(rpc, txHash)
	require.Nil(err)
	index := 0
	switch assetId {
	case common.SafePolygonChainId:
		traces, err := ethereum.RPCDebugTraceTransactionByHash(rpc, txHash)
		require.Nil(err)
		transfers, _ := ethereum.LoopCalls(common.SafeChainPolygon, common.SafePolygonChainId, txHash, traces, 0)
		for _, t := range transfers {
			if t.TokenAddress == ethereum.EthereumEmptyAddress && t.Receiver == testEthereumSafeAddress {
				index = int(t.Index)
			}
		}
	default:
		transfers, err := ethereum.GetERC20TransferLogFromBlock(ctx, rpc, common.SafeChainPolygon, int64(etx.BlockHeight))
		require.Nil(err)
		for _, t := range transfers {
			if t.TokenAddress == assetAddress && t.Receiver == testEthereumSafeAddress {
				index = int(t.Index)
			}
		}
	}
	extra := []byte{common.SafeChainPolygon}
	extra = append(extra, uuid.Must(uuid.FromString(assetId)).Bytes()...)
	extra = append(extra, b...)
	extra = append(extra, gc.HexToAddress(assetAddress).Bytes()...)
	extra = binary.BigEndian.AppendUint64(extra, uint64(index))
	extra = append(extra, amt.BigInt().Bytes()...)

	bondId := testDeployBondContract(ctx, require, node, testEthereumSafeAddress, assetId)

	holder := testPublicKey(testEthereumKeyHolder)
	out := testBuildObserverRequest(node, id, holder, common.ActionObserverHolderDeposit, extra, common.CurveSecp256k1ECDSAPolygon)
	testStep(ctx, require, node, out)

	safeAssetId := node.getBondAssetId(ctx, node.conf.PolygonKeeperDepositEntry, assetId, holder)
	require.Equal(bondId, safeAssetId)
}

func testEthereumUpdateNetworkStatus(ctx context.Context, require *require.Assertions, node *Node, blockHeight int, blockHash string) {
	id := uuid.Must(uuid.NewV4()).String()
	fee, height := 0, uint64(blockHeight)
	hash, err := hex.DecodeString(blockHash)
	require.Nil(err)

	extra := []byte{common.SafeChainPolygon}
	extra = binary.BigEndian.AppendUint64(extra, uint64(fee))
	extra = binary.BigEndian.AppendUint64(extra, height)
	extra = append(extra, hash[:]...)
	dummy := testEthereumPublicKey(testEthereumKeyDummyHolder)
	out := testBuildObserverRequest(node, id, dummy, common.ActionObserverUpdateNetworkStatus, extra, common.CurveSecp256k1ECDSAPolygon)
	testStep(ctx, require, node, out)

	info, err := node.store.ReadLatestNetworkInfo(ctx, common.SafeChainPolygon, time.Now())
	require.Nil(err)
	require.NotNil(info)
	require.Equal(byte(common.SafeChainPolygon), info.Chain)
	require.Equal(uint64(fee), info.Fee)
	require.Equal(height, info.Height)
	require.Equal(hex.EncodeToString(hash), info.Hash[2:])
}

func testEthereumUpdateAccountPrice(ctx context.Context, require *require.Assertions, node *Node) {
	id := uuid.Must(uuid.NewV4()).String()

	extra := []byte{common.SafeChainPolygon}
	extra = append(extra, uuid.Must(uuid.FromString(testAccountPriceAssetId)).Bytes()...)
	extra = binary.BigEndian.AppendUint64(extra, testAccountPriceAmount*100000000)
	extra = binary.BigEndian.AppendUint64(extra, 10000)
	dummy := testEthereumPublicKey(testEthereumKeyHolder)
	out := testBuildObserverRequest(node, id, dummy, common.ActionObserverSetOperationParams, extra, common.CurveSecp256k1ECDSAPolygon)
	testStep(ctx, require, node, out)

	plan, err := node.store.ReadLatestOperationParams(ctx, common.SafeChainPolygon, time.Now())
	require.Nil(err)
	require.Equal(testAccountPriceAssetId, plan.OperationPriceAsset)
	require.Equal(fmt.Sprint(testAccountPriceAmount), plan.OperationPriceAmount.String())
	require.Equal("0.0001", plan.TransactionMinimum.String())
}

func testEthereumSignMessage(require *require.Assertions, priv string, message []byte) []byte {
	private, _ := crypto.HexToECDSA(priv)
	publicKey := private.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	pub := crypto.CompressPubkey(publicKeyECDSA)

	hash := crypto.Keccak256Hash(fmt.Appendf(nil, "\x19Ethereum Signed Message:\n%d%s", len(message), message))
	signature, err := crypto.Sign(hash.Bytes(), private)
	require.Nil(err)
	signed := crypto.VerifySignature(pub, hash.Bytes(), signature[:64])
	require.True(signed)

	// Golang returns the recovery ID in the last byte instead of v
	// v = 27 + rid
	signature[64] += 27
	hasPrefix := testIsTxHashSignedWithPrefix(priv, hash.Bytes(), signature)
	if hasPrefix {
		signature[64] += 4
	}
	return signature
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
	address := ethereumAddressFromPriv(priv)
	return recoveredAddress != address
}

func ethereumAddressFromPriv(priv string) string {
	addr, _ := ethereum.PrivToAddress(priv)
	return addr.Hex()
}

func testEthereumPublicKey(priv string) string {
	privateKey, _ := crypto.HexToECDSA(priv)
	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)

	return hex.EncodeToString(crypto.CompressPubkey(publicKeyECDSA))
}
