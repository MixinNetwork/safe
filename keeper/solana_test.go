package keeper

import (
	"context"
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
	"github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/signer"
	"github.com/MixinNetwork/trusted-group/mtg"
	sg "github.com/gagliardetto/solana-go"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

var (
	testSolanaKeyHolder      = sg.MustPrivateKeyFromBase58("3Md1AnGnmDxSwrDjz9cbwRfGAVNvPR2pH9SGftLdeFZEx7HXSTA8seXahRH3KbjbXAAXRpqqqvLFyugLLjxE3HW8")
	testSolanaKeyObserver    = sg.MustPrivateKeyFromBase58("3NZzws9DKasavm5E6mERiiiB5qqKAze7eznzxJe9Hkq6fvSwizC9M644BToWPZnJmNPGxqfRcYaEQTtspa1wkeQ1")
	testSolanaKeyDummyHolder = sg.MustPrivateKeyFromBase58("2UVbe4ZGaX5r9oQWSSLAMHB9m6C7iAoDN8ijXSmATgv6BaBuhqk9eGNH7ALV6WL3PMFzhaMcZxtVzQZbwcQMKRHM")

	testSolanaNonceAccount = sg.MPK("FHwzoFkcHxc2xMgTPWjvyra87DBQqwGsS78yCx2EUboh")
	testSolanaBlockhash    = sg.MPK("3qmjGHDNkk6QC5G4P3SjJauD7Wgdwtgbw9p8fp4dPTqC")
	testSolanaPayerAccount = sg.MPK("FB1J65JHc1nkgSiuEpSW6fD65MJw6VBT7dN6AyMpGU9B")

	testSolanaBondAssetId         = "08823f4a-6fd4-311e-8ddd-9478e163cf91"
	testSolanaUSDTAssetId         = "218bc6f4-7927-3f8e-8568-3a3725b74361"
	testSolanaUSDTBondAssetId     = "edc249f5-d792-3091-a359-23c67ce0d595"
	testSolanaUSDTAddress         = "H7UPvz5Gouue7Joihvu9jbX4CM4jjxTh3c57FZ2Pkhva"
	testSolanaTransactionReceiver = sg.MPK("3Maas91CwJdYr1wk59buvPEnBx3dkLQpQNopfPfwUARe")
)

func TestSolanaKeeper(t *testing.T) {
	require := require.New(t)
	ctx, node, db, _, signers := testSolanaPrepare(require)

	output, err := testWriteOutput(ctx, db, node.conf.AppId, testSolanaBondAssetId, testGenerateDummyExtra(node), sequence, decimal.NewFromInt(100000000000000))
	require.Nil(err)
	action := &mtg.Action{
		UnifiedOutput: *output,
	}
	node.ProcessOutput(ctx, action)
	testSolanaObserverHolderDeposit(ctx, require, node, "51Vzfuah4LoAPwpGWEJekrFpjbUeoNa4f85SFQHN1p7pKAMBYTk6j28tpaB6oudTu3tndsiinQ7e7rgaQQx4tG1Z", common.SafeSolanaChainId, testSolanaUSDTAddress, "100000000000000")

	txHash := testSolanaProposeTransaction(ctx, require, node, testSolanaBondAssetId)
	testSolanaApproveTransaction(ctx, require, node, txHash, solana.SolanaMixinChainId, signers)
}

func testSolanaPrepare(require *require.Assertions) (context.Context, *Node, *mtg.SQLite3Store, string, []*signer.Node) {
	logger.SetLevel(logger.INFO)
	ctx, signers, _ := signer.TestPrepare(require)
	public := signer.TestFROSTPrepareKeys(ctx, require, signers, common.CurveEdwards25519Default)

	// placeholder for chain code
	chainCode := [32]byte{}

	root, err := os.MkdirTemp("", "safe-keeper-test-")
	require.Nil(err)
	node, db := testBuildNode(ctx, require, root)
	require.NotNil(node)
	timestamp, err := node.timestamp(ctx)
	require.Nil(err)
	require.Equal(node.conf.MTG.Genesis.Epoch, timestamp)
	testSpareKeys(ctx, require, node, 0, 0, 0, common.CurveEdwards25519Default)

	id := uuid.Must(uuid.NewV4()).String()
	extra := append([]byte{common.RequestRoleSigner}, chainCode[:]...)
	extra = append(extra, common.RequestFlagNone)
	out := testBuildSignerOutput(node, id, public, common.OperationTypeKeygenOutput, extra, common.CurveEdwards25519Default)
	testStep(ctx, require, node, out)
	v, err := node.store.ReadProperty(ctx, id)
	require.Nil(err)
	require.Equal("", v)
	testSpareKeys(ctx, require, node, 0, 1, 0, common.CurveEdwards25519Default)

	id = uuid.Must(uuid.NewV4()).String()
	observer := hex.EncodeToString(testSolanaKeyObserver.PublicKey().Bytes())
	occ := make([]byte, 32)
	extra = append([]byte{common.RequestRoleObserver}, occ...)
	extra = append(extra, common.RequestFlagNone)
	out = testBuildObserverRequest(node, id, observer, common.ActionObserverAddKey, extra, common.CurveEdwards25519Default)
	testStep(ctx, require, node, out)
	v, err = node.store.ReadProperty(ctx, id)
	require.Nil(err)
	require.Equal("", v)
	testSpareKeys(ctx, require, node, 0, 1, 1, common.CurveEdwards25519Default)

	batch := byte(64)
	id = uuid.Must(uuid.NewV4()).String()
	dummy := hex.EncodeToString(testSolanaKeyHolder.PublicKey().Bytes())
	out = testBuildObserverRequest(node, id, dummy, common.ActionObserverRequestSignerKeys, []byte{batch}, common.CurveEdwards25519Default)
	testStep(ctx, require, node, out)
	signerMembers := node.GetSigners()
	for i := byte(0); i < batch; i++ {
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
	testSpareKeys(ctx, require, node, 0, 1, 1, common.CurveEdwards25519Default)

	for i := 0; i < 10; i++ {
		testSolanaUpdateAccountPrice(ctx, require, node)
	}

	rid, stx := testSolanaProposeAccount(ctx, require, node, public, observer)
	testSpareKeys(ctx, require, node, 0, 0, 0, common.CurveEdwards25519Default)
	testSolanaApproveAccount(ctx, require, node, rid, stx)
	testSpareKeys(ctx, require, node, 0, 0, 0, common.CurveEdwards25519Default)
	for i := 0; i < 10; i++ {
		testSolanaUpdateNetworkStatus(ctx, require, node, 373789745, "BMgyjNfP89GiUZ4YbXrFHcWP797dAk8ZFRDZ31heKZzT")
	}

	holder := hex.EncodeToString(testSolanaKeyHolder.PublicKey().Bytes())
	safe, err := node.store.ReadSafe(ctx, holder)
	require.Nil(err)
	require.NotNil(safe)
	require.Equal(int64(0), safe.Nonce)

	return ctx, node, db, public, signers
}

func testSolanaProposeTransaction(ctx context.Context, require *require.Assertions, node *Node, rid string) string {
	holder := testSolanaKeyHolder.PublicKey().String()
	info, err := node.store.ReadLatestNetworkInfo(ctx, common.SafeChainSolana, time.Now())
	require.Nil(err)
	extra := []byte{0}
	extra = append(extra, uuid.Must(uuid.FromString(info.RequestId)).Bytes()...)
	extra = append(extra, testSolanaTransactionReceiver[:]...)
	out := testBuildHolderRequest(node, rid, holder, common.ActionSolanaSafeProposeTransaction, testSolanaBondAssetId, extra, decimal.NewFromFloat(0.0001))
	testStep(ctx, require, node, out)

	b := testReadObserverResponse(ctx, require, node, rid, common.ActionSolanaSafeProposeTransaction)
	t, err := sg.TransactionFromBytes(b)
	require.Nil(err)

	outputs := solana.ExtractOutputs(t)
	require.Len(outputs, 1)
	amt := decimal.NewFromBigInt(outputs[0].Amount, -int32(solana.NativeTokenDecimals))
	require.Equal("0.0001", amt.String())
	require.Equal(testSolanaTransactionReceiver, outputs[0].Destination)

	stx, err := node.store.ReadTransaction(ctx, t.Message.RecentBlockhash.String())
	require.Nil(err)

	require.Equal(hex.EncodeToString(b), stx.RawTransaction)
	data := fmt.Sprintf("[{\"amount\":\"0.0001\",\"receiver\":\"%s\"}]", testSolanaTransactionReceiver.String())
	require.Equal(data, stx.Data)
	require.Equal(common.RequestStateInitial, stx.State)

	return stx.TransactionHash
}

func testSolanaApproveTransaction(ctx context.Context, require *require.Assertions, node *Node, transactionHash, assetId string, signers []*signer.Node) {
	id := uuid.Must(uuid.NewV4()).String()

	tx, err := node.store.ReadTransaction(ctx, transactionHash)
	require.Nil(err)
	require.Equal(common.RequestStateInitial, tx.State)

	raw, err := hex.DecodeString(tx.RawTransaction)
	require.Nil(err)
	t, err := sg.TransactionFromBytes(raw)
	require.Nil(err)

	safe, err := node.store.ReadSafe(ctx, tx.Holder)
	require.Nil(err)

	require.Nil(solana.Sign(t, testSolanaKeyHolder))

	raw, err = t.MarshalBinary()
	require.Nil(err)
	ref := mc.Sha256Hash(raw)
	err = node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(raw))
	require.Nil(err)

	extra := uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	extra = append(extra, ref[:]...)

	out := testBuildObserverRequest(node, id, safe.Holder, common.ActionSolanaSafeApproveTransaction, extra, common.CurveEdwards25519Default)
	testStep(ctx, require, node, out)

	requests, err := node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStatePending, tx.State)

	msg, err := hex.DecodeString(requests[0].Message)
	require.Nil(err)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignInput, msg, common.CurveEdwards25519Default)
	op := signer.TestProcessOutput(ctx, require, signers, out, requests[0].RequestId)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignOutput, op.Extra, common.CurveEdwards25519Default)
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

	safeAssetId := node.getBondAssetId(ctx, node.conf.PolygonKeeperDepositEntry, assetId, safe.Holder)
	balance, err := node.store.ReadSolanaBalance(ctx, safe.Holder, assetId, safeAssetId)
	require.Nil(err)
	require.Equal(int64(0), balance.BigBalance().Int64())

	safe, err = node.store.ReadSafe(ctx, tx.Holder)
	require.Nil(err)
	require.Equal(int64(2), safe.Nonce)
}

func testSolanaObserverHolderDeposit(ctx context.Context, require *require.Assertions, node *Node, signature, assetId, assetAddress, balance string) {
	id := uuid.Must(uuid.NewV4()).String()
	amt, err := decimal.NewFromString(balance)
	require.Nil(err)

	sig, err := sg.SignatureFromBase58(signature)
	require.Nil(err)

	client := node.solanaClient()
	rpcTx, err := client.RPCGetTransaction(ctx, signature)
	require.Nil(err)
	tx, err := rpcTx.Transaction.GetTransaction()
	require.Nil(err)
	meta := rpcTx.Meta
	require.NotNil(meta)

	index := 0
	transfers, err := client.ExtractTransfersFromTransaction(ctx, tx, meta)
	require.Nil(err)

	for _, transfer := range transfers {
		if transfer.TokenAddress == assetAddress && transfer.Receiver == testSolanaTransactionReceiver.String() {
			index = int(transfer.Index)
		}
	}

	extra := []byte{common.SafeChainSolana}
	extra = append(extra, uuid.Must(uuid.FromString(assetId)).Bytes()...)
	extra = append(extra, testSolanaTransactionReceiver[:]...)
	extra = append(extra, sig[:]...)
	extra = append(extra, sg.MPK(assetAddress).Bytes()...)
	extra = binary.BigEndian.AppendUint64(extra, uint64(index))
	extra = append(extra, amt.BigInt().Bytes()...)

	holder := testSolanaKeyHolder.PublicKey()
	safeAddress := solana.GetDefaultAuthorityPDA(solana.GetMultisigPDA(holder)).String()

	bondId := testDeployBondContract(ctx, require, node, safeAddress, assetId)
	out := testBuildObserverRequest(node, id, holder.String(), common.ActionObserverHolderDeposit, extra, common.CurveEdwards25519Default)
	testStep(ctx, require, node, out)

	safeAssetId := node.getBondAssetId(ctx, node.conf.PolygonKeeperDepositEntry, assetId, holder.String())
	require.Equal(bondId, safeAssetId)
	safeBalance, err := node.store.ReadSolanaBalance(ctx, holder.String(), assetId, safeAssetId)
	require.Nil(err)
	require.Equal(balance, safeBalance.BigBalance().String())
}

func testSolanaUpdateAccountPrice(ctx context.Context, require *require.Assertions, node *Node) {
	id := uuid.Must(uuid.NewV4()).String()

	extra := []byte{common.SafeChainSolana}
	extra = append(extra, uuid.Must(uuid.FromString(testAccountPriceAssetId)).Bytes()...)
	extra = binary.BigEndian.AppendUint64(extra, testAccountPriceAmount*100000000)
	extra = binary.BigEndian.AppendUint64(extra, 10000)
	dummy := hex.EncodeToString(testSolanaKeyHolder.PublicKey().Bytes())
	out := testBuildObserverRequest(node, id, dummy, common.ActionObserverSetOperationParams, extra, common.CurveEdwards25519Default)
	testStep(ctx, require, node, out)

	plan, err := node.store.ReadLatestOperationParams(ctx, common.SafeChainSolana, time.Now())
	require.Nil(err)
	require.Equal(testAccountPriceAssetId, plan.OperationPriceAsset)
	require.Equal(fmt.Sprint(testAccountPriceAmount), plan.OperationPriceAmount.String())
	require.Equal("0.0001", plan.TransactionMinimum.String())
}

func testSolanaRecipient() []byte {
	extra := binary.BigEndian.AppendUint16(nil, 0)
	extra = append(extra, 1, 1)
	id := uuid.FromStringOrNil(testSafeBondReceiverId)
	extra = append(extra, id.Bytes()...)
	extra = append(extra, testSolanaNonceAccount[:]...)
	extra = append(extra, testSolanaBlockhash[:]...)
	extra = append(extra, testSolanaPayerAccount[:]...)
	return extra
}

func testSolanaProposeAccount(ctx context.Context, require *require.Assertions, node *Node, signer, observer string) (string, *sg.Transaction) {
	id := uuid.Must(uuid.NewV4()).String()
	holder := hex.EncodeToString(testSolanaKeyHolder.PublicKey().Bytes())

	extra := testSolanaRecipient()
	price := decimal.NewFromFloat(testAccountPriceAmount)
	out := testBuildHolderRequest(node, id, holder, common.ActionSolanaSafeProposeAccount, testAccountPriceAssetId, extra, price)
	testStep(ctx, require, node, out)
	b := testReadObserverResponse(ctx, require, node, id, common.ActionSolanaSafeProposeAccount)
	stx, err := sg.TransactionFromBytes(b)
	require.Nil(err)

	safeAddress := solana.GetDefaultAuthorityPDA(solana.GetMultisigPDA(testSolanaKeyHolder.PublicKey())).String()
	require.Equal(safeAddress, solana.GetAuthorityAddressFromCreateTx(stx).String())

	sp, err := node.store.ReadSafeProposal(ctx, id)
	require.Nil(err)
	require.Equal(id, sp.RequestId)
	require.Equal(holder, sp.Holder)
	require.Equal(signer, sp.Signer)
	require.Equal(observer, sp.Observer)
	require.Equal(safeAddress, sp.Address)
	require.Equal(byte(1), sp.Threshold)
	require.Len(sp.Receivers, 1)
	require.Equal(testSafeBondReceiverId, sp.Receivers[0])

	return id, stx
}

func testSolanaApproveAccount(ctx context.Context, require *require.Assertions, node *Node, rid string, stx *sg.Transaction) {
	approveRequestId := uuid.Must(uuid.NewV4()).String()
	holder := hex.EncodeToString(testSolanaKeyHolder.PublicKey().Bytes())

	safeAddress := solana.GetAuthorityAddressFromCreateTx(stx).String()
	sp, err := node.store.ReadSafeProposalByAddress(ctx, safeAddress)
	require.Nil(err)

	outputs := solana.ExtractOutputs(stx)
	require.Len(outputs, 0)

	content, err := stx.Message.MarshalBinary()
	require.Nil(err)

	signature, err := testSolanaKeyHolder.Sign(content)
	require.Nil(err)
	require.False(signature.IsZero())

	extra := uuid.FromStringOrNil(rid).Bytes()
	extra = append(extra, signature[:]...)
	out := testBuildObserverRequest(node, approveRequestId, holder, common.ActionSolanaSafeApproveAccount, extra, common.CurveEdwards25519Default)
	testStep(ctx, require, node, out)

	safe, err := node.store.ReadSafe(ctx, holder)
	require.Nil(err)
	require.Equal(SafeStateApproved, int(safe.State))
	require.Equal(approveRequestId, safe.RequestId)
	require.Equal(holder, safe.Holder)
	require.Equal(sp.Holder, safe.Holder)
	require.Equal(sp.Signer, safe.Signer)
	require.Equal(sp.Observer, safe.Observer)
	require.Equal(safeAddress, safe.Address)
	require.Equal(byte(1), safe.Threshold)
	require.Len(safe.Receivers, 1)
	require.Equal(testSafeBondReceiverId, safe.Receivers[0])
}

func testSolanaUpdateNetworkStatus(ctx context.Context, require *require.Assertions, node *Node, blockHeight int, blockHash string) {
	id := uuid.Must(uuid.NewV4()).String()
	fee, height := 0, uint64(blockHeight)
	hash, err := sg.HashFromBase58(blockHash)
	require.Nil(err)

	extra := []byte{common.SafeChainSolana}
	extra = binary.BigEndian.AppendUint64(extra, uint64(fee))
	extra = binary.BigEndian.AppendUint64(extra, height)
	extra = append(extra, hash[:]...)
	dummy := hex.EncodeToString(testSolanaKeyDummyHolder.PublicKey().Bytes())
	out := testBuildObserverRequest(node, id, dummy, common.ActionObserverUpdateNetworkStatus, extra, common.CurveEdwards25519Default)
	testStep(ctx, require, node, out)
}
