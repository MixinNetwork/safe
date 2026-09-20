package bitcoin

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	mixincommon "github.com/MixinNetwork/mixin/common"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestWitnessAccountEncodingAndScriptUtilities(t *testing.T) {
	holder, holderPublic := btcec.PrivKeyFromBytes([]byte{1})
	_, signerPublic := btcec.PrivKeyFromBytes([]byte{2})
	_, observerPublic := btcec.PrivKeyFromBytes([]byte{3})
	account, err := BuildWitnessScriptAccount(
		hex.EncodeToString(holderPublic.SerializeCompressed()),
		hex.EncodeToString(signerPublic.SerializeCompressed()),
		hex.EncodeToString(observerPublic.SerializeCompressed()),
		TimeLockMinimum,
		ChainBitcoin,
	)
	require.NoError(t, err)

	raw := account.Marshal()
	decoded, err := UnmarshalWitnessScriptAccount(raw)
	require.NoError(t, err)
	require.Equal(t, account, decoded)
	for _, truncated := range [][]byte{
		nil,
		raw[:8],
		raw[:8+2+len(account.Script)],
	} {
		_, err := UnmarshalWitnessScriptAccount(truncated)
		require.Error(t, err)
	}

	encoded, err := EncodeAddress(account.Script, ChainBitcoin)
	require.NoError(t, err)
	require.Equal(t, account.Address, encoded)
	require.True(t, CheckMultisigHolderSignerScript(account.Script))
	require.False(t, CheckMultisigHolderSignerScript(holderPublic.SerializeCompressed()))
	require.Panics(t, func() { _, _ = EncodeAddress([]byte{txscript.OP_TRUE}, ChainBitcoin) })

	pkScript, err := ParseAddress(account.Address, ChainBitcoin)
	require.NoError(t, err)
	extracted, err := ExtractPkScriptAddr(pkScript, ChainBitcoin)
	require.NoError(t, err)
	require.Equal(t, account.Address, extracted)
	_, err = ExtractPkScriptAddr([]byte{txscript.OP_TRUE}, ChainBitcoin)
	require.Error(t, err)
	_, err = ExtractPkScriptAddr([]byte{txscript.OP_PUSHDATA4}, ChainBitcoin)
	require.Error(t, err)

	hash := HashMessageForSignature("coverage", ChainBitcoin)
	signature := ecdsa.Sign(holder, hash).Serialize()
	require.NoError(t, VerifySignatureDER(hex.EncodeToString(holderPublic.SerializeCompressed()), hash, signature))
	require.Error(t, VerifySignatureDER("invalid", hash, signature))
	require.Error(t, VerifySignatureDER(hex.EncodeToString(holderPublic.SerializeCompressed()), hash, []byte{0xff}))
	require.Error(t, VerifySignatureDER(hex.EncodeToString(holderPublic.SerializeCompressed()), []byte("wrong"), signature))
}

func TestWitnessAccountRejectsKeysLocksAndUnsupportedNetworks(t *testing.T) {
	_, holder := btcec.PrivKeyFromBytes([]byte{1})
	_, signer := btcec.PrivKeyFromBytes([]byte{2})
	_, observer := btcec.PrivKeyFromBytes([]byte{3})
	holderHex := hex.EncodeToString(holder.SerializeCompressed())
	signerHex := hex.EncodeToString(signer.SerializeCompressed())
	observerHex := hex.EncodeToString(observer.SerializeCompressed())

	require.Error(t, VerifyHolderKey("invalid"))
	_, err := BuildWitnessScriptAccount("invalid", signerHex, observerHex, TimeLockMinimum, ChainBitcoin)
	require.Error(t, err)
	_, err = BuildWitnessScriptAccount(holderHex, signerHex, observerHex, TimeLockMinimum-time.Second, ChainBitcoin)
	require.Error(t, err)
	_, err = BuildWitnessScriptAccount(holderHex, signerHex, observerHex, TimeLockMaximum+time.Second, ChainBitcoin)
	require.Error(t, err)
	litecoin, err := BuildWitnessScriptAccount(holderHex, signerHex, observerHex, TimeLockMinimum, ChainLitecoin)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(litecoin.Address, "ltc1"))

	require.Equal(t, int64(1_000), ValueDust(ChainBitcoin))
	require.Equal(t, int64(10_000), ValueDust(ChainLitecoin))
	require.Panics(t, func() { ValueDust(0xff) })
	require.NotZero(t, protocolVersion(ChainBitcoin))
	require.Equal(t, uint32(70_015), protocolVersion(ChainLitecoin))
	require.Panics(t, func() { protocolVersion(0xff) })
	require.Equal(t, "bc", NetConfig(ChainBitcoin).Bech32HRPSegwit)
	require.Equal(t, "ltc", NetConfig(ChainLitecoin).Bech32HRPSegwit)
	require.Panics(t, func() { NetConfig(0xff) })
	require.Equal(t, InputTypeP2WPKHAccoutant, checkScriptType(make([]byte, 33)))
	require.Equal(t, InputTypeP2WSHMultisigHolderSigner, checkScriptType(make([]byte, 101)))
	require.Panics(t, func() { checkScriptType([]byte{1}) })
}

func TestBitcoinAmountsTimingFeesAndMessages(t *testing.T) {
	require.Equal(t, int64(123_456_789), ParseSatoshi("1.23456789"))
	require.Equal(t, int64(-100_000_000), ParseSatoshi("-1"))
	require.Panics(t, func() { ParseSatoshi("0.000000001") })
	require.Panics(t, func() { ParseSatoshi("100000000000000000000000000") })

	_, err := ParseAddress("address", 0xff)
	require.Error(t, err)
	_, err = ParseAddress("invalid", ChainBitcoin)
	require.Error(t, err)

	require.Equal(t, int64(6), ParseSequence(time.Hour, ChainBitcoin))
	require.Equal(t, int64(24), ParseSequence(time.Hour, ChainLitecoin))
	require.Equal(t, int64(0xffff), ParseSequence(TimeLockMaximum, ChainLitecoin))
	require.Panics(t, func() { ParseSequence(TimeLockMinimum-time.Second, ChainBitcoin) })
	require.Panics(t, func() { ParseSequence(TimeLockMinimum, 0xff) })
	require.Equal(t, 20*time.Minute, BlocksDuration(ChainBitcoin, 2))
	require.Equal(t, 5*time.Minute, BlocksDuration(ChainLitecoin, 2))
	require.Panics(t, func() { BlocksDuration(0xff, 1) })

	for _, fee := range []int64{2, 1_000} {
		require.True(t, CheckFeeRange(fee, ChainBitcoin))
	}
	require.False(t, CheckFeeRange(1, ChainBitcoin))
	require.False(t, CheckFeeRange(1_001, ChainBitcoin))
	for _, fee := range []int64{1, 20} {
		require.True(t, CheckFeeRange(fee, ChainLitecoin))
	}
	require.False(t, CheckFeeRange(0, ChainLitecoin))
	require.False(t, CheckFeeRange(21, ChainLitecoin))
	require.Panics(t, func() { CheckFeeRange(1, 0xff) })

	require.NotEqual(t, HashMessageForSignature("message", ChainBitcoin), HashMessageForSignature("message", ChainLitecoin))
	require.Panics(t, func() { HashMessageForSignature("message", 0xff) })
	require.False(t, IsInsufficientInputError(nil))
	require.False(t, IsInsufficientInputError(errors.New("other")))
	insufficient := BuildInsufficientInputError("main", 1, 2)
	require.True(t, IsInsufficientInputError(insufficient))
	require.EqualError(t, insufficient, "insufficient main 1 2")

	encoder := mixincommon.NewEncoder()
	WriteBytes(encoder, []byte{1, 2, 3})
	require.Equal(t, []byte{0, 3, 1, 2, 3}, encoder.Bytes())
}

func TestBitcoinPublicDerivationChecks(t *testing.T) {
	_, public := btcec.PrivKeyFromBytes([]byte{9})
	publicHex := hex.EncodeToString(public.SerializeCompressed())
	chainCode := bytes.Repeat([]byte{7}, 32)
	extended, child, err := DeriveBIP32(publicHex, chainCode, 1, 2, 3)
	require.NoError(t, err)
	require.NotEmpty(t, extended)
	require.Len(t, child, 66)
	require.NoError(t, CheckDerivation(publicHex, chainCode, 3))
	require.Error(t, CheckDerivation("invalid", chainCode, 1))
	_, _, err = DeriveBIP32("invalid", chainCode, 1)
	require.Error(t, err)
}

func TestBitcoinTransactionConstructionFailureBoundaries(t *testing.T) {
	_, holder := btcec.PrivKeyFromBytes([]byte{1})
	_, signer := btcec.PrivKeyFromBytes([]byte{2})
	_, observer := btcec.PrivKeyFromBytes([]byte{3})
	account, err := BuildWitnessScriptAccount(
		hex.EncodeToString(holder.SerializeCompressed()),
		hex.EncodeToString(signer.SerializeCompressed()),
		hex.EncodeToString(observer.SerializeCompressed()),
		TimeLockMinimum,
		ChainBitcoin,
	)
	require.NoError(t, err)
	input := &Input{
		TransactionHash: strings.Repeat("0", 63) + "1",
		Satoshi:         100_000,
		Script:          bytes.Clone(account.Script),
		Sequence:        account.Sequence,
	}

	packet, err := BuildPartiallySignedTransaction(
		[]*Input{input},
		[]*Output{{Address: securityTestBitcoinReceiver, Satoshi: 50_000}},
		nil,
		ChainBitcoin,
	)
	require.NoError(t, err)
	require.NotEmpty(t, packet.Hash())
	_, err = UnmarshalPartiallySignedTransaction([]byte{0xff})
	require.Error(t, err)

	invalidHash := *input
	invalidHash.TransactionHash = "invalid"
	_, err = BuildPartiallySignedTransaction([]*Input{&invalidHash}, nil, nil, ChainBitcoin)
	require.ErrorContains(t, err, "addInputs(main)")

	invalidOutput := *input
	_, err = BuildPartiallySignedTransaction(
		[]*Input{&invalidOutput}, []*Output{{Address: "invalid", Satoshi: 1_000}}, nil, ChainBitcoin,
	)
	require.ErrorContains(t, err, "addOutput")

	dustInput := *input
	_, err = BuildPartiallySignedTransaction(
		[]*Input{&dustInput}, []*Output{{Address: securityTestBitcoinReceiver, Satoshi: 1}}, nil, ChainBitcoin,
	)
	require.ErrorContains(t, err, "addOutput")

	insufficientInput := *input
	_, err = BuildPartiallySignedTransaction(
		[]*Input{&insufficientInput},
		[]*Output{{Address: securityTestBitcoinReceiver, Satoshi: insufficientInput.Satoshi + 1}},
		nil,
		ChainBitcoin,
	)
	require.True(t, IsInsufficientInputError(err))

	_, otherHolder := btcec.PrivKeyFromBytes([]byte{4})
	_, otherSigner := btcec.PrivKeyFromBytes([]byte{5})
	_, otherObserver := btcec.PrivKeyFromBytes([]byte{6})
	otherAccount, err := BuildWitnessScriptAccount(
		hex.EncodeToString(otherHolder.SerializeCompressed()),
		hex.EncodeToString(otherSigner.SerializeCompressed()),
		hex.EncodeToString(otherObserver.SerializeCompressed()),
		TimeLockMinimum,
		ChainBitcoin,
	)
	require.NoError(t, err)
	first := *input
	second := *input
	second.TransactionHash = strings.Repeat("0", 63) + "2"
	second.Script = otherAccount.Script
	_, err = BuildPartiallySignedTransaction([]*Input{&first, &second}, nil, nil, ChainBitcoin)
	require.ErrorContains(t, err, "input address")

	recovery := *input
	recovery.RouteBackup = true
	recovery.Sequence = 0
	_, err = BuildPartiallySignedTransaction([]*Input{&recovery}, nil, nil, ChainBitcoin)
	require.ErrorContains(t, err, "invalid sequence")

	_, err = addOutput(wire.NewMsgTx(2), "invalid", 1_000, ChainBitcoin)
	require.Error(t, err)
	added, err := addOutput(wire.NewMsgTx(2), securityTestBitcoinReceiver, 1, ChainBitcoin)
	require.NoError(t, err)
	require.False(t, added)
}

func TestSpendSignedTransactionDecodeAndFeeInputFailures(t *testing.T) {
	_, err := SpendSignedTransaction("not-hex", nil, "00", ChainBitcoin)
	require.Error(t, err)
	_, err = SpendSignedTransaction("00", nil, "00", ChainBitcoin)
	require.Error(t, err)

	previous := chainhash.Hash{1}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&previous, 0), nil, nil))
	tx.AddTxOut(wire.NewTxOut(1_000, []byte{txscript.OP_TRUE}))
	raw, err := MarshalWiredTransaction(tx, wire.WitnessEncoding, ChainBitcoin)
	require.NoError(t, err)
	_, err = SpendSignedTransaction(hex.EncodeToString(raw), nil, "not-hex", ChainBitcoin)
	require.Error(t, err)

	accountant, _ := btcec.PrivKeyFromBytes([]byte{7})
	_, err = SpendSignedTransaction(hex.EncodeToString(raw), []*Input{{
		TransactionHash: "invalid",
		Satoshi:         10_000,
	}}, hex.EncodeToString(accountant.Serialize()), ChainBitcoin)
	require.ErrorContains(t, err, "addInputs(fee)")
	require.Panics(t, func() {
		_, _ = MarshalWiredTransaction(tx, wire.WitnessEncoding, 0xff)
	})
}
