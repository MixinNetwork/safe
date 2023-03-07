package signer

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/test-go/testify/assert"
)

const (
	testBitcoinAddress     = "bc1q7erq8pvv665nuzmrqrn5vyc3kcd8v4vtafvdd8mkt9h05qz57l3qks2lsd"
	testBitcoinKeyHolder   = "04b1d2c7d2e9c630d840fc9ba452617d6d963ceba43b31d7f16403612d08353c"
	testBitcoinKeyObserver = "d2b9dabc8745d0f15956dc6808c33910bb455bb01ed04cdf4e56f88da76d48c1"
)

type bitcoinUTXO struct {
	TransactionHash string
	Index           uint32
	Satoshi         int64
	Script          []byte
	Sequence        uint32
}

func TestCMPBitcoinSignObserverSigner(t *testing.T) {
	assert := assert.New(t)
	ctx, nodes := TestPrepare(assert)

	public := TestCMPPrepareKeys(ctx, assert, nodes, common.CurveSecp256k1ECDSABitcoin)

	mpc, _ := hex.DecodeString(public)
	wsa, err := bitcoinMultisigWitnessScriptHash(mpc)
	assert.Nil(err)
	assert.Equal(testBitcoinAddress, wsa.Address)

	mainInputs := []*bitcoin.Input{{
		TransactionHash: "94b7bc957680be9db51d47dfb5db9166048deb8c85fc00466d3a1ce974df25ab",
		Index:           1,
		Satoshi:         28560,
		Script:          wsa.Script,
		Sequence:        wsa.Sequence,
		RouteBackup:     true,
	}}
	feeInputs := []*bitcoin.Input{{
		TransactionHash: "94b7bc957680be9db51d47dfb5db9166048deb8c85fc00466d3a1ce974df25ab",
		Index:           0,
		Satoshi:         10000,
		Script:          wsa.Script,
		Sequence:        wsa.Sequence,
		RouteBackup:     true,
	}}
	outputs := []*bitcoin.Output{{
		Address: testBitcoinAddress,
		Satoshi: 10000,
	}}
	hash, raw, err := bitcoinBuildTransactionObserverSigner(ctx, assert, nodes, public, mainInputs, feeInputs, outputs, 10)
	assert.Nil(err)
	assert.Equal("0f522f14d9c176d861f9bbee35d1e6e6b20050e4476f08dfd3b893161a6adfc2", hash)
	assert.Equal("0200000002ab25df74e91c3a6d4600fc858ceb8d046691dbb5df471db59dbe807695bcb794010000000007004000ab25df74e91c3a6d4600fc858ceb8d046691dbb5df471db59dbe807695bcb794000000000007004000031027000000000000220020f64603858cd6a93e0b6300e7461311b61a76558bea58d69f76596efa0054f7e28048000000000000220020f64603858cd6a93e0b6300e7461311b61a76558bea58d69f76596efa0054f7e2101d000000000000220020f64603858cd6a93e0b6300e7461311b61a76558bea58d69f76596efa0054f7e200000000", raw)
}

func bitcoinBuildTransactionObserverSigner(ctx context.Context, assert *assert.Assertions, nodes []*Node, mpc string, mainInputs, feeInputs []*bitcoin.Input, outputs []*bitcoin.Output, fvb int64) (string, string, error) {
	psbt, err := bitcoin.BuildPartiallySignedTransaction(mainInputs, feeInputs, outputs, fvb)
	assert.Nil(err)
	tx := psbt.PSBT().UnsignedTx
	assert.Equal(psbt.Hash, tx.TxHash().String())
	assert.Equal(int64(10000), tx.TxOut[0].Value)
	assert.Equal(int64(18560), tx.TxOut[1].Value)
	assert.Equal(int64(7440), tx.TxOut[2].Value)

	ob, _ := hex.DecodeString(testBitcoinKeyObserver)
	observer, _ := btcec.PrivKeyFromBytes(ob)

	for idx := range tx.TxIn {
		pin := psbt.PSBT().Inputs[idx]
		hash := psbt.SigHash(idx)

		sig := testCMPSign(ctx, assert, nodes, mpc, hash, common.CurveSecp256k1ECDSABitcoin)
		_, err = ecdsa.ParseSignature(sig)
		assert.Nil(err)
		sig = append(sig, byte(txscript.SigHashAll))
		der, err := ecdsa.ParseDERSignature(sig[:len(sig)-1])
		assert.Nil(err)
		pub, _ := hex.DecodeString(mpc)
		signer, _ := btcutil.NewAddressPubKey(pub, &chaincfg.MainNetParams)
		assert.True(der.Verify(hash, signer.PubKey()))

		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, []byte{})
		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, sig)

		signature := ecdsa.Sign(observer, hash)
		sig = append(signature.Serialize(), byte(txscript.SigHashAll))
		ss := hex.EncodeToString(sig)
		switch idx {
		case 0:
			assert.Equal("304402207e5584a796fe82118d2f511b426862494bf843083fc1a7ccdd5c634d63a4c18e0220501dc3a6805f3c4ae6a84cbd680ad5fa56fc5f40646bbc2d4c423d68d231366001", ss)
		case 1:
			assert.Equal("3045022100fc35f5c85688420a200cb41e7cd08fea2ad05e36667fd7d1b22936958dfb9b5b02200e89037b9111c452b358f5e9115c67d2032e8cc48e23c699a50ef7a6290feda001", ss)
		}

		der, err = ecdsa.ParseDERSignature(sig[:len(sig)-1])
		assert.Nil(err)
		assert.True(der.Verify(hash, observer.PubKey()))

		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, sig)
		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, []byte{})
		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, pin.WitnessScript)
	}

	var rawBuffer bytes.Buffer
	err = psbt.PSBT().UnsignedTx.BtcEncode(&rawBuffer, wire.ProtocolVersion, wire.BaseEncoding)
	assert.Nil(err)
	var signedBuffer bytes.Buffer
	err = tx.BtcEncode(&signedBuffer, wire.ProtocolVersion, wire.WitnessEncoding)
	assert.Nil(err)
	signed := hex.EncodeToString(signedBuffer.Bytes())
	raw := hex.EncodeToString(rawBuffer.Bytes())
	assert.Contains(signed, raw[8:len(raw)-8])
	logger.Println(signed)

	return tx.TxHash().String(), raw, nil
}

func TestCMPBitcoinSignHolderSigner(t *testing.T) {
	assert := assert.New(t)
	ctx, nodes := TestPrepare(assert)

	public := TestCMPPrepareKeys(ctx, assert, nodes, common.CurveSecp256k1ECDSABitcoin)

	mpc, _ := hex.DecodeString(public)
	wsa, err := bitcoinMultisigWitnessScriptHash(mpc)
	assert.Nil(err)
	assert.Equal(testBitcoinAddress, wsa.Address)

	mainInputs := []*bitcoin.Input{{
		TransactionHash: "d9666734caf98802d9ae1ffdcfa32914b4cabaafff18a363b73175c03a6e7df9",
		Index:           0,
		Satoshi:         10000,
		Script:          wsa.Script,
		Sequence:        wsa.Sequence,
		RouteBackup:     false,
	}}
	feeInputs := []*bitcoin.Input{{
		TransactionHash: "d9666734caf98802d9ae1ffdcfa32914b4cabaafff18a363b73175c03a6e7df9",
		Index:           1,
		Satoshi:         30800,
		Script:          wsa.Script,
		Sequence:        wsa.Sequence,
		RouteBackup:     false,
	}}
	outputs := []*bitcoin.Output{{
		Address: testBitcoinAddress,
		Satoshi: 10000,
	}}
	hash, raw, err := bitcoinBuildTransactionHolderSigner(ctx, assert, nodes, public, mainInputs, feeInputs, outputs, 10)
	assert.Nil(err)
	assert.Equal("94b7bc957680be9db51d47dfb5db9166048deb8c85fc00466d3a1ce974df25ab", hash)
	assert.Equal("0200000002f97d6e3ac07531b763a318ffafbacab41429a3cffd1faed90288f9ca346766d90000000000fffffffff97d6e3ac07531b763a318ffafbacab41429a3cffd1faed90288f9ca346766d90100000000ffffffff021027000000000000220020f64603858cd6a93e0b6300e7461311b61a76558bea58d69f76596efa0054f7e2906f000000000000220020f64603858cd6a93e0b6300e7461311b61a76558bea58d69f76596efa0054f7e200000000", raw)
}

func bitcoinBuildTransactionHolderSigner(ctx context.Context, assert *assert.Assertions, nodes []*Node, mpc string, mainInputs, feeInputs []*bitcoin.Input, outputs []*bitcoin.Output, fvb int64) (string, string, error) {
	psbt, err := bitcoin.BuildPartiallySignedTransaction(mainInputs, feeInputs, outputs, fvb)
	assert.Nil(err)
	tx := psbt.PSBT().UnsignedTx
	assert.Equal(psbt.Hash, tx.TxHash().String())
	assert.Equal(int64(10000), tx.TxOut[0].Value)
	assert.Equal(int64(28560), tx.TxOut[1].Value)

	hb, _ := hex.DecodeString(testBitcoinKeyHolder)
	holder, _ := btcec.PrivKeyFromBytes(hb)

	for idx := range tx.TxIn {
		pin := psbt.PSBT().Inputs[idx]
		hash := psbt.SigHash(idx)

		signature := ecdsa.Sign(holder, hash)
		sig := append(signature.Serialize(), byte(txscript.SigHashAll))
		ss := hex.EncodeToString(sig)
		switch idx {
		case 0:
			assert.Equal("3045022100bd2367ff7821fa9efcf9e99dadfe82beca550918db6b736a93d198f8549b9fe402201f84d4e0eda3f9fc8ba9d425b43077285f20be97cb6a8b86039651dd94893b8f01", ss)
		case 1:
			assert.Equal("3044022069004da9a43f8919904ba96a431d5a06bb129cadf04ef4087dfb09d98759bab302203f6e490599ab6562d8858455d63afecb0908520cd9d42db1cb60e30d72db8a1101", ss)
		}

		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, []byte{})

		der, err := ecdsa.ParseDERSignature(sig[:len(sig)-1])
		assert.Nil(err)
		assert.True(der.Verify(hash, holder.PubKey()))
		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, sig)

		sig = testCMPSign(ctx, assert, nodes, mpc, hash, common.CurveSecp256k1ECDSABitcoin)
		_, err = ecdsa.ParseSignature(sig)
		assert.Nil(err)
		sig = append(sig, byte(txscript.SigHashAll))
		der, err = ecdsa.ParseDERSignature(sig[:len(sig)-1])
		assert.Nil(err)
		pub, _ := hex.DecodeString(mpc)
		signer, _ := btcutil.NewAddressPubKey(pub, &chaincfg.MainNetParams)
		assert.True(der.Verify(hash, signer.PubKey()))

		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, sig)
		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, []byte{1})
		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, pin.WitnessScript)
	}

	var rawBuffer bytes.Buffer
	err = psbt.PSBT().UnsignedTx.BtcEncode(&rawBuffer, wire.ProtocolVersion, wire.BaseEncoding)
	assert.Nil(err)
	var signedBuffer bytes.Buffer
	err = tx.BtcEncode(&signedBuffer, wire.ProtocolVersion, wire.WitnessEncoding)
	assert.Nil(err)
	signed := hex.EncodeToString(signedBuffer.Bytes())
	raw := hex.EncodeToString(rawBuffer.Bytes())
	assert.Contains(signed, raw[8:len(raw)-8])
	logger.Println(signed)

	return tx.TxHash().String(), raw, nil
}

func bitcoinMultisigWitnessScriptHash(mpc []byte) (*bitcoin.WitnessScriptAccount, error) {
	seed, _ := hex.DecodeString(testBitcoinKeyHolder)
	_, hk := btcec.PrivKeyFromBytes(seed)
	seed, _ = hex.DecodeString(testBitcoinKeyObserver)
	_, dk := btcec.PrivKeyFromBytes(seed)

	holder := hex.EncodeToString(hk.SerializeCompressed())
	observer := hex.EncodeToString(dk.SerializeCompressed())
	signer := hex.EncodeToString(mpc)
	return bitcoin.BuildWitnessScriptAccount(holder, signer, observer, time.Minute*60)
}
