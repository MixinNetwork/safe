package bitcoin

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

const securityTestBitcoinReceiver = "bc1q7wqpsk0ckquckd7v0e38uqkscjh7v0ncelqpz459hueet5uknamqrlgp2d"

func TestBitcoinCustodySignatureCommitsToSpend(t *testing.T) {
	require := require.New(t)
	holder, holderPublic := btcec.PrivKeyFromBytes([]byte{1})
	signer, signerPublic := btcec.PrivKeyFromBytes([]byte{2})
	_, observerPublic := btcec.PrivKeyFromBytes([]byte{3})
	holderHex := hex.EncodeToString(holderPublic.SerializeCompressed())
	signerHex := hex.EncodeToString(signerPublic.SerializeCompressed())
	observerHex := hex.EncodeToString(observerPublic.SerializeCompressed())

	account, err := BuildWitnessScriptAccount(
		holderHex,
		signerHex,
		observerHex,
		TimeLockMinimum,
		ChainBitcoin,
	)
	require.NoError(err)

	input := &Input{
		TransactionHash: "0000000000000000000000000000000000000000000000000000000000000001",
		Index:           0,
		Satoshi:         100_000,
		Script:          account.Script,
		Sequence:        account.Sequence,
	}
	packet, err := BuildPartiallySignedTransaction(
		[]*Input{input},
		[]*Output{{Address: securityTestBitcoinReceiver, Satoshi: 60_000}},
		nil,
		ChainBitcoin,
	)
	require.NoError(err)
	packet = SignPartiallySignedTransaction(packet.Marshal(), holder)
	packet = SignPartiallySignedTransaction(packet.Marshal(), signer)

	tx, err := packet.SignedTransaction(holderHex, signerHex, observerHex)
	require.NoError(err)
	custodyPkScript, err := ParseAddress(account.Address, ChainBitcoin)
	require.NoError(err)
	require.NoError(securityTestExecuteBitcoinInput(tx, 0, custodyPkScript, input.Satoshi))

	// The Safe signatures use SIGHASH_ALL|ANYONECANPAY. A fee payer may add
	// and sign an input, but cannot change any existing input or output.
	const feeAmount = int64(10_000)
	feeKey, feePublic := btcec.PrivKeyFromBytes([]byte{4})
	signedBuffer, err := MarshalWiredTransaction(tx, wire.WitnessEncoding, ChainBitcoin)
	require.NoError(err)
	withFeeInput, err := SpendSignedTransaction(
		hex.EncodeToString(signedBuffer),
		[]*Input{{
			TransactionHash: "0000000000000000000000000000000000000000000000000000000000000002",
			Index:           0,
			Satoshi:         feeAmount,
		}},
		hex.EncodeToString(feeKey.Serialize()),
		ChainBitcoin,
	)
	require.NoError(err)
	publicHash := address.Hash160(feePublic.SerializeCompressed())
	feeAddress, err := address.NewAddressWitnessPubKeyHash(publicHash, NetConfig(ChainBitcoin))
	require.NoError(err)
	feePkScript, err := txscript.PayToAddrScript(feeAddress)
	require.NoError(err)
	require.NoError(securityTestExecuteBitcoinInput(withFeeInput, 0, custodyPkScript, input.Satoshi))
	require.NoError(securityTestExecuteBitcoinInput(withFeeInput, 1, feePkScript, feeAmount))

	mutations := []struct {
		name  string
		apply func(*wire.MsgTx)
	}{
		{name: "recipient value", apply: func(tx *wire.MsgTx) { tx.TxOut[0].Value++ }},
		{name: "recipient script", apply: func(tx *wire.MsgTx) { tx.TxOut[0].PkScript[5] ^= 1 }},
		{name: "change value", apply: func(tx *wire.MsgTx) { tx.TxOut[1].Value++ }},
		{name: "remove output", apply: func(tx *wire.MsgTx) { tx.TxOut = tx.TxOut[:len(tx.TxOut)-1] }},
		{name: "add output", apply: func(tx *wire.MsgTx) {
			tx.AddTxOut(wire.NewTxOut(1, []byte{txscript.OP_TRUE}))
		}},
		{name: "version", apply: func(tx *wire.MsgTx) { tx.Version++ }},
		{name: "locktime", apply: func(tx *wire.MsgTx) { tx.LockTime++ }},
		{name: "custody outpoint", apply: func(tx *wire.MsgTx) { tx.TxIn[0].PreviousOutPoint.Index++ }},
		{name: "custody sequence", apply: func(tx *wire.MsgTx) { tx.TxIn[0].Sequence-- }},
	}

	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := tx.Copy()
			mutation.apply(candidate)
			require.Error(securityTestExecuteBitcoinInput(candidate, 0, custodyPkScript, input.Satoshi))
		})
	}
}

func TestBitcoinRecoveryThresholdAndTimelock(t *testing.T) {
	holder, holderPublic := btcec.PrivKeyFromBytes([]byte{1})
	signer, signerPublic := btcec.PrivKeyFromBytes([]byte{2})
	observer, observerPublic := btcec.PrivKeyFromBytes([]byte{3})
	holderHex := hex.EncodeToString(holderPublic.SerializeCompressed())
	signerHex := hex.EncodeToString(signerPublic.SerializeCompressed())
	observerHex := hex.EncodeToString(observerPublic.SerializeCompressed())

	account, err := BuildWitnessScriptAccount(
		holderHex,
		signerHex,
		observerHex,
		TimeLockMinimum,
		ChainBitcoin,
	)
	require.NoError(t, err)
	custodyPkScript, err := ParseAddress(account.Address, ChainBitcoin)
	require.NoError(t, err)

	build := func(t *testing.T, routeBackup bool, sequence uint32, signers ...*btcec.PrivateKey) *PartiallySignedTransaction {
		t.Helper()
		input := &Input{
			TransactionHash: "0000000000000000000000000000000000000000000000000000000000000003",
			Index:           0,
			Satoshi:         100_000,
			Script:          account.Script,
			Sequence:        sequence,
			RouteBackup:     routeBackup,
		}
		packet, err := BuildPartiallySignedTransaction(
			[]*Input{input},
			[]*Output{{Address: securityTestBitcoinReceiver, Satoshi: 60_000}},
			nil,
			ChainBitcoin,
		)
		require.NoError(t, err)
		for _, key := range signers {
			packet = SignPartiallySignedTransaction(packet.Marshal(), key)
		}
		return packet
	}

	for _, test := range []struct {
		name    string
		signers []*btcec.PrivateKey
	}{
		{name: "observer and holder", signers: []*btcec.PrivateKey{observer, holder}},
		{name: "observer and signer", signers: []*btcec.PrivateKey{observer, signer}},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := build(t, true, account.Sequence, test.signers...)
			tx, err := packet.SignedTransaction(holderHex, signerHex, observerHex)
			require.NoError(t, err)
			require.NoError(t, securityTestExecuteBitcoinInput(tx, 0, custodyPkScript, 100_000))
		})
	}

	t.Run("observer is mandatory", func(t *testing.T) {
		packet := build(t, true, account.Sequence, holder, signer)
		_, err := packet.SignedTransaction(holderHex, signerHex, observerHex)
		require.Error(t, err)
	})

	t.Run("normal route requires holder and signer", func(t *testing.T) {
		packet := build(t, false, account.Sequence, holder, observer)
		_, err := packet.SignedTransaction(holderHex, signerHex, observerHex)
		require.Error(t, err)
	})

	t.Run("relative timelock is enforced", func(t *testing.T) {
		require.Greater(t, account.Sequence, uint32(1))
		packet := build(t, true, account.Sequence-1, observer, holder)
		tx, err := packet.SignedTransaction(holderHex, signerHex, observerHex)
		require.NoError(t, err)
		require.Error(t, securityTestExecuteBitcoinInput(tx, 0, custodyPkScript, 100_000))
	})
}

func securityTestExecuteBitcoinInput(tx *wire.MsgTx, index int, pkScript []byte, amount int64) error {
	fetcher := txscript.NewCannedPrevOutputFetcher(pkScript, amount)
	hashes := txscript.NewTxSigHashes(tx, fetcher)
	vm, err := txscript.NewEngine(
		pkScript,
		tx,
		index,
		txscript.StandardVerifyFlags,
		nil,
		hashes,
		amount,
		fetcher,
	)
	if err != nil {
		return err
	}
	return vm.Execute()
}
