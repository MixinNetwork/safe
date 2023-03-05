package keeper

import (
	"bytes"
	"context"
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

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/domains/mvm"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/nfo/store"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/signer"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid"
	"github.com/pelletier/go-toml"
	"github.com/shopspring/decimal"
	"github.com/test-go/testify/assert"
	"github.com/test-go/testify/require"
)

const (
	testAccountPriceAssetId          = "31d2ea9c-95eb-3355-b65b-ba096853bc18"
	testBondAssetId                  = "9390ca53-2ec5-3a65-acee-9e149ae38452"
	testSafeBondReceiverId           = "e459de8b-4edd-44ff-a119-b1d707f8521a"
	testBitcoinKeyHolderPrivate      = "04b1d2c7d2e9c630d840fc9ba452617d6d963ceba43b31d7f16403612d08353c"
	testBitcoinKeyObserverPrivate    = "d2b9dabc8745d0f15956dc6808c33910bb455bb01ed04cdf4e56f88da76d48c1"
	testBitcoinKeyAccountantPrivate  = "743602ca7e2723e7dd510e611957cfdcbb517dff0c5b1877472e35b0f19e0063"
	testBitcoinKeyDummyHolderPrivate = "75d5f311c8647e3a1d84a0d975b6e50b8c6d3d7f195365320077f41c6a165155"
	testSafePublicKey                = "bc1q7erq8pvv665nuzmrqrn5vyc3kcd8v4vtafvdd8mkt9h05qz57l3qks2lsd"
	testSafeAccountant               = "bc1qkczcrtknyhs228xg9nvujjvs96x56cf9l4q9za"
	testTransactionReceiver          = "bc1ql0up0wwazxt6xlj84u9fnvhnagjjetcn7h4z5xxvd0kf5xuczjgqq2aehc"
	testBitcoinDepositMainHash       = "8260f125afdb1a85b540f0066cd9db18d488a3891b5fa5595c73f40435502d09"
)

func TestKeeper(t *testing.T) {
	logger.SetLevel(logger.VERBOSE)
	require := require.New(t)
	ctx, signers := signer.TestPrepare(assert.New(t))
	mpc := signer.TestCMPPrepareKeys(ctx, assert.New(t), signers, common.CurveSecp256k1ECDSABitcoin)

	root, err := os.MkdirTemp("", "safe-keeper-test")
	require.Nil(err)
	node := testBuildNode(ctx, require, root)
	require.NotNil(node)
	timestamp, err := node.timestamp(ctx)
	require.Nil(err)
	require.Equal(time.Unix(0, node.conf.MTG.Genesis.Timestamp), timestamp)
	testSpareKeys(ctx, require, node, 0, 0, 0, 0)

	id := uuid.Must(uuid.NewV4()).String()
	out := testBuildSignerOutput(node, id, mpc, common.OperationTypeKeygenOutput, []byte{common.RequestRoleSigner})
	testStep(ctx, require, node, out)
	v, err := node.store.ReadProperty(ctx, id)
	require.Nil(err)
	require.Equal("", v)
	testSpareKeys(ctx, require, node, 0, 1, 0, 0)

	id = uuid.Must(uuid.NewV4()).String()
	observer := testPublicKey(testBitcoinKeyObserverPrivate)
	out = testBuildObserverRequest(node, id, observer, common.ActionObserverAddKey, []byte{common.RequestRoleObserver})
	testStep(ctx, require, node, out)
	v, err = node.store.ReadProperty(ctx, id)
	require.Nil(err)
	require.Equal("", v)
	testSpareKeys(ctx, require, node, 0, 1, 1, 0)

	id = uuid.Must(uuid.NewV4()).String()
	accountant := testPublicKey(testBitcoinKeyAccountantPrivate)
	out = testBuildObserverRequest(node, id, accountant, common.ActionObserverAddKey, []byte{common.RequestRoleAccountant})
	testStep(ctx, require, node, out)
	v, err = node.store.ReadProperty(ctx, id)
	require.Nil(err)
	require.Equal("", v)
	wka, err := bitcoin.BuildWitnessKeyAccount(accountant)
	require.Nil(err)
	require.Equal(testSafeAccountant, wka.Address)
	testSpareKeys(ctx, require, node, 0, 1, 1, 1)

	batch := byte(64)
	id = uuid.Must(uuid.NewV4()).String()
	dummy := testPublicKey(testBitcoinKeyDummyHolderPrivate)
	out = testBuildObserverRequest(node, id, dummy, common.ActionObserverRequestSignerKeys, []byte{batch})
	testStep(ctx, require, node, out)
	for i := byte(0); i < batch; i++ {
		pid := mixin.UniqueConversationID(id, fmt.Sprintf("%8d", i))
		pid = mixin.UniqueConversationID(pid, fmt.Sprintf("MTG:%v:%d", node.signer.Genesis.Members, node.signer.Genesis.Threshold))
		v, _ := node.store.ReadProperty(ctx, pid)
		var om map[string]any
		json.Unmarshal([]byte(v), &om)
		b, _ := hex.DecodeString(om["memo"].(string))
		b = common.AESDecrypt(node.signerAESKey[:], b)
		o, err := common.DecodeOperation(b)
		require.Nil(err)
		require.Equal(pid, o.Id)
	}
	testSpareKeys(ctx, require, node, 0, 1, 1, 1)

	for i := 0; i < 10; i++ {
		testUpdateAccountPrice(ctx, require, node)
	}
	rid, publicKey := testSafeProposeAccount(ctx, require, node, mpc, observer, accountant)
	testSpareKeys(ctx, require, node, 0, 0, 0, 0)
	testSafeApproveAccount(ctx, require, node, mpc, observer, accountant, rid, publicKey)
	testSpareKeys(ctx, require, node, 0, 0, 0, 0)
	for i := 0; i < 10; i++ {
		testUpdateNetworkStatus(ctx, require, node)
	}

	input := &bitcoin.Input{
		TransactionHash: "8c9fe0bcb7c6577606553ef9441f15a331fe1c6b44f9a995cad4d76263eb2ab0",
		Index:           0, Satoshi: 10000,
	}
	testObserverAccountantDeposit(ctx, require, node, accountant, input, 1)
	input = &bitcoin.Input{
		TransactionHash: "9c2d9652c75269611fd4ebea5161c793ba5ff94bddfab9453705aada60ea5141",
		Index:           0, Satoshi: 10000,
	}
	testObserverAccountantDeposit(ctx, require, node, accountant, input, 2)

	bondId := testDeployBondContract(ctx, require, node, testSafePublicKey, SafeBitcoinChainId)
	require.Equal(testBondAssetId, bondId)
	node.ProcessOutput(ctx, &mtg.Output{AssetID: bondId, Amount: decimal.NewFromInt(1000000), CreatedAt: time.Now()})
	input = &bitcoin.Input{
		TransactionHash: "0f522f14d9c176d861f9bbee35d1e6e6b20050e4476f08dfd3b893161a6adfc2",
		Index:           0, Satoshi: 10000,
	}
	testObserverHolderDeposit(ctx, require, node, mpc, observer, input, 1)
	input = &bitcoin.Input{
		TransactionHash: "0f522f14d9c176d861f9bbee35d1e6e6b20050e4476f08dfd3b893161a6adfc2",
		Index:           1, Satoshi: 18560,
	}
	testObserverHolderDeposit(ctx, require, node, mpc, observer, input, 2)

	transactionHash := testSafeProposeTransaction(ctx, require, node, mpc, accountant, bondId)
	testSafeApproveTransaction(ctx, require, node, transactionHash, assert.New(t), signers)
	testSpareKeys(ctx, require, node, 0, 0, 0, 0)
}

func testUpdateAccountPrice(ctx context.Context, require *require.Assertions, node *Node) {
	id := uuid.Must(uuid.NewV4()).String()

	extra := []byte{SafeChainBitcoin}
	extra = append(extra, uuid.Must(uuid.FromString(testAccountPriceAssetId)).Bytes()...)
	extra = binary.BigEndian.AppendUint64(extra, 100000000)
	dummy := testPublicKey(testBitcoinKeyDummyHolderPrivate)
	out := testBuildObserverRequest(node, id, dummy, common.ActionObserverSetPrice, extra)
	testStep(ctx, require, node, out)

	assetId, amount, err := node.store.ReadAccountPrice(ctx, SafeChainBitcoin)
	require.Nil(err)
	require.Equal(testAccountPriceAssetId, assetId)
	require.Equal("1", amount.String())
}

func testUpdateNetworkStatus(ctx context.Context, require *require.Assertions, node *Node) {
	id := uuid.Must(uuid.NewV4()).String()
	fee, height := bitcoinMinimumFeeRate, uint64(772793)
	hash, _ := crypto.HashFromString("00000000000000000003f2b0cedf601824c02ba9ad129ca3531502dca525c635")

	extra := []byte{SafeChainBitcoin}
	extra = binary.BigEndian.AppendUint64(extra, uint64(fee))
	extra = binary.BigEndian.AppendUint64(extra, height)
	extra = append(extra, hash[:]...)
	dummy := testPublicKey(testBitcoinKeyDummyHolderPrivate)
	out := testBuildObserverRequest(node, id, dummy, common.ActionObserverUpdateNetworkStatus, extra)
	testStep(ctx, require, node, out)

	info, err := node.store.ReadNetworkInfo(ctx, SafeChainBitcoin)
	require.Nil(err)
	require.NotNil(info)
	require.Equal(byte(SafeChainBitcoin), info.Chain)
	require.Equal(uint64(fee), info.Fee)
	require.Equal(height, info.Height)
	require.Equal(hash.String(), info.Hash)
}

func testSafeApproveTransaction(ctx context.Context, require *require.Assertions, node *Node, transactionHash string, assert *assert.Assertions, signers []*signer.Node) {
	id := uuid.Must(uuid.NewV4()).String()

	ab, _ := hex.DecodeString(testBitcoinKeyAccountantPrivate)
	accountant, _ := btcec.PrivKeyFromBytes(ab)

	tx, _ := node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateInitial, tx.State)
	safe, _ := node.store.ReadSafe(ctx, tx.Holder)

	hb, _ := hex.DecodeString(testBitcoinKeyHolderPrivate)
	holder, _ := btcec.PrivKeyFromBytes(hb)
	msg := bitcoin.HashMessageForSignature(transactionHash)
	sig := ecdsa.Sign(holder, msg).Serialize()
	extra := uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	extra = append(extra, sig...)

	out := testBuildObserverRequest(node, id, testPublicKey(testBitcoinKeyHolderPrivate), common.ActionBitcoinSafeApproveTransaction, extra)
	testStep(ctx, require, node, out)
	requests, err := node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Nil(err)
	require.Len(requests, 2)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStatePending, tx.State)

	msg, _ = hex.DecodeString(requests[0].Message)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignInput, msg)
	op := signer.TestCMPProcessOutput(ctx, assert, signers, out, requests[0].RequestId)
	out = testBuildSignerOutput(node, requests[0].RequestId, safe.Signer, common.OperationTypeSignOutput, op.Extra)
	testStep(ctx, require, node, out)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStatePending)
	require.Len(requests, 1)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Len(requests, 1)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStatePending, tx.State)

	msg, _ = hex.DecodeString(requests[1].Message)
	out = testBuildSignerOutput(node, requests[1].RequestId, safe.Signer, common.OperationTypeSignInput, msg)
	op = signer.TestCMPProcessOutput(ctx, assert, signers, out, requests[1].RequestId)
	out = testBuildSignerOutput(node, requests[1].RequestId, safe.Signer, common.OperationTypeSignOutput, op.Extra)
	testStep(ctx, require, node, out)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateInitial)
	require.Len(requests, 0)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStatePending)
	require.Len(requests, 0)
	requests, _ = node.store.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateDone)
	require.Len(requests, 2)
	tx, _ = node.store.ReadTransaction(ctx, transactionHash)
	require.Equal(common.RequestStateDone, tx.State)

	var bundle []*common.IndexedBytes
	signed := make(map[int][]byte)
	for _, r := range requests {
		b, _ := hex.DecodeString(r.Signature.String)
		bundle = append(bundle, &common.IndexedBytes{Index: r.OutputIndex, Data: b})
		signed[r.OutputIndex] = b
	}
	txHash, _ := hex.DecodeString(transactionHash)
	mb := append(txHash, common.EncodeIndexedBytesSorted(bundle)...)
	exk := common.MVMHash(mb)
	rid := mixin.UniqueConversationID(transactionHash, hex.EncodeToString(exk))
	b := testReadObserverResponse(ctx, require, node, rid, common.ActionBitcoinSafeApproveTransaction)
	assert.Equal(mb, b)

	b, _ = hex.DecodeString(tx.RawTransaction)
	rtx, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)
	msgTx := rtx.MsgTx()
	for idx := range msgTx.TxIn {
		pop := msgTx.TxIn[idx].PreviousOutPoint
		hash := rtx.SigHashes[idx*32 : idx*32+32]
		utxo, _ := node.store.ReadBitcoinUTXO(ctx, pop.Hash.String(), int(pop.Index))
		if msig := signed[idx]; msig != nil {
			signature := ecdsa.Sign(holder, hash)
			sig := append(signature.Serialize(), byte(txscript.SigHashAll))
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, []byte{})
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)

			msig = append(msig, byte(txscript.SigHashAll))
			der, _ := ecdsa.ParseDERSignature(msig[:len(msig)-1])
			pub, _ := hex.DecodeString(safe.Signer)
			signer, _ := btcutil.NewAddressPubKey(pub, &chaincfg.MainNetParams)
			require.True(der.Verify(hash, signer.PubKey()))
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, msig)
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, []byte{1})

			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, utxo.Script)
		} else {
			signature := ecdsa.Sign(accountant, hash)
			sig := append(signature.Serialize(), byte(txscript.SigHashAll))
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, utxo.Script)
		}
	}

	var signedBuffer bytes.Buffer
	msgTx.BtcEncode(&signedBuffer, wire.ProtocolVersion, wire.WitnessEncoding)
	logger.Println(hex.EncodeToString(signedBuffer.Bytes()))
}

func testSafeProposeTransaction(ctx context.Context, require *require.Assertions, node *Node, signer, accountant, bondId string) string {
	id := uuid.Must(uuid.NewV4()).String()
	holder := testPublicKey(testBitcoinKeyHolderPrivate)
	out := testBuildHolderRequest(node, id, holder, common.ActionBitcoinSafeProposeTransaction, bondId, []byte(testTransactionReceiver), decimal.NewFromFloat(0.000123))
	testStep(ctx, require, node, out)

	balance, err := node.store.ReadAccountantBalance(ctx, holder)
	require.Nil(err)
	require.Equal("0", balance.String())

	b := testReadObserverResponse(ctx, require, node, id, common.ActionBitcoinSafeProposeTransaction)
	require.Equal("0020009a5e07cb83c94d64331130afa3094e61ed3cf99467ce2505b72d89d1932afc01230200000004c2df6a1a1693b8d3df086f47e45000b2e6e6d135eebbf961d876c1d9142f520f0000000000ffffffffc2df6a1a1693b8d3df086f47e45000b2e6e6d135eebbf961d876c1d9142f520f0100000000ffffffffb02aeb6362d7d4ca95a9f9446b1cfe31a3151f44f93e55067657c6b7bce09f8c0000000000ffffffff4151ea60daaa053745b9fadd4bf95fba93c76151eaebd41f616952c752962d9c0000000000ffffffff030c30000000000000220020fbf817b9dd1197a37e47af0a99b2f3ea252caf13f5ea2a18cc6bec9a1b981490843f000000000000220020f64603858cd6a93e0b6300e7461311b61a76558bea58d69f76596efa0054f7e2443e000000000000160014b60581aed325e0a51cc82cd9c949902e8d4d6125000000000080494d1623ee647dcb1088086ba1de0410bec76b17108a040b0cc89bcfc55498b5d3218edfa8b3f79315f8fe6ad9a95657670fd15ce380a72203e0ad5a07bb097400ac3111ed1a6464c9f0cc420c245f790b94bebbbe9419c429200690a62ccae512854f03c7cfc1280c54630870a7fbe81f6c51500c1727d00161bb89e648f0680000000000000fdc", hex.EncodeToString(b))
	raw, err := bitcoin.UnmarshalPartiallySignedTransaction(b)
	require.Nil(err)
	require.Equal("009a5e07cb83c94d64331130afa3094e61ed3cf99467ce2505b72d89d1932afc", raw.Hash)
	require.Equal(int64(4060), raw.Fee)
	require.Equal("0200000004c2df6a1a1693b8d3df086f47e45000b2e6e6d135eebbf961d876c1d9142f520f0000000000ffffffffc2df6a1a1693b8d3df086f47e45000b2e6e6d135eebbf961d876c1d9142f520f0100000000ffffffffb02aeb6362d7d4ca95a9f9446b1cfe31a3151f44f93e55067657c6b7bce09f8c0000000000ffffffff4151ea60daaa053745b9fadd4bf95fba93c76151eaebd41f616952c752962d9c0000000000ffffffff030c30000000000000220020fbf817b9dd1197a37e47af0a99b2f3ea252caf13f5ea2a18cc6bec9a1b981490843f000000000000220020f64603858cd6a93e0b6300e7461311b61a76558bea58d69f76596efa0054f7e2443e000000000000160014b60581aed325e0a51cc82cd9c949902e8d4d612500000000", hex.EncodeToString(raw.Raw))

	tx := raw.MsgTx()
	require.Len(tx.TxOut, 3)
	main := tx.TxOut[0]
	require.Equal(int64(12300), main.Value)
	script, _ := txscript.ParsePkScript(main.PkScript)
	addr, _ := script.Address(&chaincfg.MainNetParams)
	require.Equal(testTransactionReceiver, addr.EncodeAddress())
	change := tx.TxOut[1]
	require.Equal(int64(16260), change.Value)
	script, _ = txscript.ParsePkScript(change.PkScript)
	addr, _ = script.Address(&chaincfg.MainNetParams)
	require.Equal(testSafePublicKey, addr.EncodeAddress())
	fee := tx.TxOut[2]
	require.Equal(int64(15940), fee.Value)
	script, _ = txscript.ParsePkScript(fee.PkScript)
	addr, _ = script.Address(&chaincfg.MainNetParams)
	require.Equal(testSafeAccountant, addr.EncodeAddress())

	stx, err := node.store.ReadTransaction(ctx, raw.Hash)
	require.Nil(err)
	require.Equal(hex.EncodeToString(raw.Marshal()), stx.RawTransaction)
	require.Equal("0.0000406", stx.Fee.String())
	require.Equal(common.RequestStateInitial, stx.State)

	return stx.TransactionHash
}

func testObserverHolderDeposit(ctx context.Context, require *require.Assertions, node *Node, signer, observer string, input *bitcoin.Input, t int) {
	id := uuid.Must(uuid.NewV4()).String()
	hash, _ := crypto.HashFromString(input.TransactionHash)
	extra := []byte{SafeChainBitcoin}
	extra = append(extra, uuid.Must(uuid.FromString(SafeBitcoinChainId)).Bytes()...)
	extra = append(extra, hash[:]...)
	extra = binary.BigEndian.AppendUint64(extra, uint64(input.Index))
	extra = append(extra, big.NewInt(input.Satoshi).Bytes()...)

	holder := testPublicKey(testBitcoinKeyHolderPrivate)
	wsa, _ := bitcoin.BuildWitnessScriptAccount(holder, signer, observer, bitcoinTimeLockDuration(ctx))

	out := testBuildObserverRequest(node, id, holder, common.ActionObserverHolderDeposit, extra)
	testStep(ctx, require, node, out)

	balance, err := node.store.ReadAccountantBalance(ctx, holder)
	require.Nil(err)
	require.Equal("0.0002", balance.String())

	mainInputs, feeInputs, err := node.store.ListAllBitcoinUTXOsForHolder(ctx, holder)
	require.Nil(err)
	require.Len(mainInputs, 1*t)
	require.Len(feeInputs, 2)
	utxo := mainInputs[t-1]
	require.Equal(uint32(input.Index), utxo.Index)
	require.Equal(input.Satoshi, utxo.Satoshi)
	require.Equal(wsa.Script, utxo.Script)
	require.Equal(hash.String(), utxo.TransactionHash)
	require.Equal(uint32(0x400007), wsa.Sequence)
	require.True(bitcoin.CheckMultisigHolderSignerScript(utxo.Script))
}

func testObserverAccountantDeposit(ctx context.Context, require *require.Assertions, node *Node, accountant string, input *bitcoin.Input, t int) {
	id := uuid.Must(uuid.NewV4()).String()
	hash, _ := crypto.HashFromString(input.TransactionHash)
	extra := []byte{SafeChainBitcoin}
	extra = append(extra, uuid.Must(uuid.FromString(SafeBitcoinChainId)).Bytes()...)
	extra = append(extra, hash[:]...)
	extra = binary.BigEndian.AppendUint64(extra, uint64(input.Index))
	extra = append(extra, big.NewInt(input.Satoshi).Bytes()...)

	wka, _ := bitcoin.BuildWitnessKeyAccount(accountant)

	holder := testPublicKey(testBitcoinKeyHolderPrivate)
	out := testBuildObserverRequest(node, id, holder, common.ActionObserverAccountantDepost, extra)
	testStep(ctx, require, node, out)

	balance, err := node.store.ReadAccountantBalance(ctx, holder)
	require.Nil(err)
	require.Equal(fmt.Sprint(0.0001*float64(t)), balance.String())

	mainInputs, feeInputs, err := node.store.ListAllBitcoinUTXOsForHolder(ctx, holder)
	require.Nil(err)
	require.Len(mainInputs, 0)
	require.Len(feeInputs, 1*t)
	utxo := feeInputs[t-1]
	require.Equal(uint32(input.Index), utxo.Index)
	require.Equal(input.Satoshi, utxo.Satoshi)
	require.Equal(wka.Script, utxo.Script)
	require.Equal(hash.String(), utxo.TransactionHash)
	require.Equal(uint32(bitcoin.MaxTransactionSequence), utxo.Sequence)
	require.False(bitcoin.CheckMultisigHolderSignerScript(utxo.Script))
}

func testSafeProposeAccount(ctx context.Context, require *require.Assertions, node *Node, signer, observer, accountant string) (string, string) {
	id := uuid.Must(uuid.NewV4()).String()
	holder := testPublicKey(testBitcoinKeyHolderPrivate)
	extra := testRecipient()
	out := testBuildHolderRequest(node, id, holder, common.ActionBitcoinSafeProposeAccount, testAccountPriceAssetId, extra, decimal.NewFromInt(1))
	testStep(ctx, require, node, out)
	b := testReadObserverResponse(ctx, require, node, id, common.ActionBitcoinSafeProposeAccount)
	wsa, aaddr, err := bitcoin.UnmarshalWitnessScriptAccountWitAccountant(b)
	require.Equal(testSafePublicKey, wsa.Address)
	require.Equal(uint32(0x400007), wsa.Sequence)
	require.Equal(testSafeAccountant, aaddr)

	safe, err := node.store.ReadSafeProposal(ctx, id)
	require.Nil(err)
	require.Equal(id, safe.RequestId)
	require.Equal(holder, safe.Holder)
	require.Equal(signer, safe.Signer)
	require.Equal(observer, safe.Observer)
	require.Equal(accountant, safe.Accountant)
	public, err := bitcoin.BuildWitnessScriptAccount(holder, signer, observer, bitcoinTimeLockDuration(ctx))
	require.Nil(err)
	require.Equal(testSafePublicKey, public.Address)
	require.Equal(public.Address, safe.Address)
	require.Equal(byte(1), safe.Threshold)
	require.Len(safe.Receivers, 1)
	require.Equal(testSafeBondReceiverId, safe.Receivers[0])

	return id, wsa.Address
}

func testSafeApproveAccount(ctx context.Context, require *require.Assertions, node *Node, signer, observer, accountant string, rid, publicKey string) {
	id := uuid.Must(uuid.NewV4()).String()
	holder := testPublicKey(testBitcoinKeyHolderPrivate)
	hash := bitcoin.HashMessageForSignature(publicKey)
	hb, _ := hex.DecodeString(testBitcoinKeyHolderPrivate)
	hp, _ := btcec.PrivKeyFromBytes(hb)
	signature := ecdsa.Sign(hp, hash)
	extra := uuid.FromStringOrNil(rid).Bytes()
	extra = append(extra, signature.Serialize()...)
	out := testBuildObserverRequest(node, id, holder, common.ActionBitcoinSafeApproveAccount, extra)
	testStep(ctx, require, node, out)
	b := testReadObserverResponse(ctx, require, node, id, common.ActionBitcoinSafeApproveAccount)
	wsa, aaddr, err := bitcoin.UnmarshalWitnessScriptAccountWitAccountant(b)
	require.Equal(testSafePublicKey, wsa.Address)
	require.Equal(uint32(0x400007), wsa.Sequence)
	require.Equal(testSafeAccountant, aaddr)

	safe, err := node.store.ReadSafe(ctx, holder)
	require.Nil(err)
	require.Equal(id, safe.RequestId)
	require.Equal(holder, safe.Holder)
	require.Equal(signer, safe.Signer)
	require.Equal(observer, safe.Observer)
	require.Equal(accountant, safe.Accountant)
	public, err := bitcoin.BuildWitnessScriptAccount(holder, signer, observer, bitcoinTimeLockDuration(ctx))
	require.Nil(err)
	require.Equal(testSafePublicKey, public.Address)
	require.Equal(public.Address, safe.Address)
	require.Equal(byte(1), safe.Threshold)
	require.Len(safe.Receivers, 1)
	require.Equal(testSafeBondReceiverId, safe.Receivers[0])
}

func testStep(ctx context.Context, require *require.Assertions, node *Node, out *mtg.Output) {
	node.ProcessOutput(ctx, out)
	timestamp, err := node.timestamp(ctx)
	require.Nil(err)
	require.Equal(out.CreatedAt.UTC(), timestamp.UTC())
	req, err := node.store.ReadPendingRequest(ctx)
	require.Nil(err)
	require.NotNil(req)
	err = req.VerifyFormat()
	require.Nil(err)
	err = node.processRequest(ctx, req)
	require.Nil(err)
	req, err = node.store.ReadPendingRequest(ctx)
	require.Nil(err)
	require.Nil(req)
}

func testSpareKeys(ctx context.Context, require *require.Assertions, node *Node, hc, sc, oc, ac int) {
	for r, c := range map[int]int{
		common.RequestRoleHolder:     hc,
		common.RequestRoleSigner:     sc,
		common.RequestRoleObserver:   oc,
		common.RequestRoleAccountant: ac,
	} {
		skc, err := node.store.CountSpareKeys(ctx, common.CurveSecp256k1ECDSABitcoin, r)
		require.Nil(err)
		require.Equal(c, skc)
	}
}

func testReadObserverResponse(ctx context.Context, require *require.Assertions, node *Node, id string, typ byte) []byte {
	v, _ := node.store.ReadProperty(ctx, id)
	var om map[string]any
	json.Unmarshal([]byte(v), &om)
	require.Equal(node.conf.ObserverUserId, om["receivers"].([]any)[0])
	require.Equal(node.conf.ObserverAssetId, om["asset_id"])
	require.Equal("1", om["amount"])
	b, _ := hex.DecodeString(om["memo"].(string))
	b = common.AESDecrypt(node.observerAESKey[:], b)
	op, err := common.DecodeOperation(b)
	require.Nil(err)
	require.Equal(typ, op.Type)
	require.Equal(id, op.Id)
	require.Len(op.Extra, 32)
	v, _ = node.store.ReadProperty(ctx, hex.EncodeToString(op.Extra))
	b, _ = hex.DecodeString(v)
	return b
}

func testBuildHolderRequest(node *Node, id, public string, action byte, assetId string, extra []byte, amount decimal.Decimal) *mtg.Output {
	op := &common.Operation{
		Id:     id,
		Type:   action,
		Curve:  common.CurveSecp256k1ECDSABitcoin,
		Public: public,
		Extra:  extra,
	}
	memo := base64.RawURLEncoding.EncodeToString(op.Encode())
	return &mtg.Output{
		AssetID:         assetId,
		Memo:            memo,
		TransactionHash: crypto.NewHash([]byte(op.Id)),
		Amount:          amount,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

func testBuildObserverRequest(node *Node, id, public string, action byte, extra []byte) *mtg.Output {
	op := &common.Operation{
		Id:     id,
		Type:   action,
		Curve:  common.CurveSecp256k1ECDSABitcoin,
		Public: public,
		Extra:  extra,
	}
	memo := common.Base91Encode(node.encryptObserverOperation(op))
	return &mtg.Output{
		Sender:          node.conf.ObserverUserId,
		AssetID:         node.conf.ObserverAssetId,
		Memo:            memo,
		TransactionHash: crypto.NewHash([]byte(op.Id)),
		Amount:          decimal.New(1, 1),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

func testBuildSignerOutput(node *Node, id, public string, action byte, extra []byte) *mtg.Output {
	op := &common.Operation{
		Id:    id,
		Type:  action,
		Curve: common.CurveSecp256k1ECDSABitcoin,
		Extra: extra,
	}
	switch action {
	case common.OperationTypeKeygenInput:
		op.Public = hex.EncodeToString(common.ShortSum(public))
	case common.OperationTypeSignInput:
		op.Public = hex.EncodeToString(common.ShortSum(public))
	case common.OperationTypeKeygenOutput:
		op.Public = public
	case common.OperationTypeSignOutput:
		op.Public = public
	}
	memo := mtg.EncodeMixinExtra("", id, string(node.encryptSignerOperation(op)))
	return &mtg.Output{
		AssetID:         node.conf.AssetId,
		Memo:            memo,
		TransactionHash: crypto.NewHash([]byte(op.Id)),
		Amount:          decimal.New(1, 1),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

func testDeployBondContract(ctx context.Context, require *require.Assertions, node *Node, addr, assetId string) string {
	safe, _ := node.store.ReadSafeByAddress(ctx, addr)
	asset, _ := node.fetchAssetMeta(ctx, assetId)
	err := abi.GetOrDeployFactoryAsset("https://geth.mvm.dev", os.Getenv("MVM_DEPLOYER"), asset.AssetId, asset.Symbol, asset.Name, safe.Holder)
	require.Nil(err)
	bond := abi.GetFactoryAssetAddress(assetId, asset.Symbol, asset.Name, safe.Holder)
	assetKey := strings.ToLower(bond.String())
	err = mvm.VerifyAssetKey(assetKey)
	require.Nil(err)
	asset, _ = node.fetchAssetMeta(ctx, mvm.GenerateAssetId(assetKey).String())
	return asset.AssetId
}

func testBuildNode(ctx context.Context, require *require.Assertions, root string) *Node {
	f, _ := os.ReadFile("../config/example.toml")
	var conf struct {
		Keeper *Configuration `toml:"keeper"`
		Signer struct {
			MTG *mtg.Configuration `toml:"mtg"`
		} `toml:"signer"`
	}
	err := toml.Unmarshal(f, &conf)
	require.Nil(err)

	conf.Keeper.StoreDir = root
	if !strings.HasPrefix(conf.Keeper.StoreDir, "/tmp/") {
		panic(root)
	}
	kd, err := OpenSQLite3Store(conf.Keeper.StoreDir + "/safe.sqlite3")
	require.Nil(err)

	db, err := store.OpenBadger(ctx, conf.Keeper.StoreDir+"/mtg")
	require.Nil(err)
	group, err := mtg.BuildGroup(ctx, db, conf.Keeper.MTG)
	require.NotNil(err)
	require.Nil(group)

	node := NewNode(kd, group, conf.Keeper, conf.Signer.MTG)
	return node
}

func testRecipient() []byte {
	extra := []byte{1, 1}
	id := uuid.FromStringOrNil(testSafeBondReceiverId)
	return append(extra, id.Bytes()...)
}

func testPublicKey(pub string) string {
	seed, _ := hex.DecodeString(pub)
	_, dk := btcec.PrivKeyFromBytes(seed)
	return hex.EncodeToString(dk.SerializeCompressed())
}
