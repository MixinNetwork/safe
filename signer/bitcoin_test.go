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
	"github.com/btcsuite/btcd/wire"
	"github.com/test-go/testify/require"
)

const (
	testBitcoinAddress       = "bc1qmhvg7ksmvzn6yhmn7yvvhkm9d3vquvz55se5zaxv80la99hkfrzs7dqupy"
	testBitcoinKeyHolder     = "52250bb9b9edc5d54466182778a6470a5ee34033c215c92dd250b9c2ce543556"
	testBitcoinKeyObserver   = "35fe01cbdc659810854615319b51899b78966c513f0515ee9d77ef6016090221"
	testBitcoinKeyAccountant = "3d1f5a749578b2726bb6efd8d9656cb9be216879550980c633ac338828e1e79a"
)

type bitcoinUTXO struct {
	TransactionHash string
	Index           uint32
	Satoshi         int64
	Script          []byte
	Sequence        uint32
}

func TestCMPBitcoinSignObserverSigner(t *testing.T) {
	require := require.New(t)
	ctx, nodes := TestPrepare(require)

	public := TestCMPPrepareKeys(ctx, require, nodes, common.CurveSecp256k1ECDSABitcoin)

	mpc, _ := hex.DecodeString(public)
	wsa, err := bitcoinMultisigWitnessScriptHash(mpc)
	require.Nil(err)
	require.Equal(testBitcoinAddress, wsa.Address)
	require.Equal("2103911c1ef3960be7304596cfa6073b1d65ad43b421a4c272142cc7a8369b510c56ac7c2102bf0a7fa4b7905a0de5ab60a5322529e1a591ddd1ee53df82e751e8adb4bed08cac937c8292632102021d499c26abd9c11f4aec84c0ffc3c2145342771843cfab041e098b87d85c6bad56b29268935287", hex.EncodeToString(wsa.Script))
	require.Equal(uint32(6), wsa.Sequence)

	mainInputs := []*bitcoin.Input{{
		TransactionHash: "32395db91b46168f154966813e394886691d66d181e3d1507f0bb040731f2d6d",
		Index:           2,
		Satoshi:         71200,
		Script:          wsa.Script,
		Sequence:        wsa.Sequence,
		RouteBackup:     true,
	}, {
		TransactionHash: "32395db91b46168f154966813e394886691d66d181e3d1507f0bb040731f2d6d",
		Index:           1,
		Satoshi:         90000,
		Script:          wsa.Script,
		Sequence:        wsa.Sequence,
		RouteBackup:     true,
	}}
	outputs := []*bitcoin.Output{{
		Address: testBitcoinAddress,
		Satoshi: 10000,
	}}
	tx, raw, err := bitcoinBuildTransactionObserverSigner(ctx, require, nodes, public, mainInputs, outputs)
	require.Nil(err)
	require.Equal("5e6a41217fe34489e6136edb041397d1761ffad9db3cbf4d1e13e8144f864c19", tx.TxHash().String())
	require.Equal("02000000026d2d1f7340b00b7f50d1e381d1661d698648393e816649158f16461bb95d39320200000000060000006d2d1f7340b00b7f50d1e381d1661d698648393e816649158f16461bb95d3932010000000006000000021027000000000000220020ddd88f5a1b60a7a25f73f118cbdb656c580e3054a4334174cc3bffd296f648c5a04e020000000000220020ddd88f5a1b60a7a25f73f118cbdb656c580e3054a4334174cc3bffd296f648c500000000", raw)

	priv, _ := hex.DecodeString(testBitcoinKeyAccountant)
	_, publicKey := btcec.PrivKeyFromBytes(priv)
	apk, _ := btcutil.NewAddressPubKey(publicKey.SerializeCompressed(), &chaincfg.MainNetParams)
	feeInputs := []*bitcoin.Input{{
		TransactionHash: "1b7336254fb420d010d75621624e53174d658f046c8b6cd7e935306fb399981d",
		Index:           0,
		Satoshi:         10007,
		Script:          apk.ScriptAddress(),
	}}
	var signedBuffer bytes.Buffer
	tx.BtcEncode(&signedBuffer, wire.ProtocolVersion, wire.WitnessEncoding)
	hash, raw, err := bitcoin.SpendSignedTransaction(hex.EncodeToString(signedBuffer.Bytes()), feeInputs, testBitcoinKeyAccountant, bitcoin.ChainBitcoin)
	logger.Println(raw)
	require.Nil(err)
	require.Equal("3cbe8ac67374b48066c5f3e3fe45ca9c7043aa29c4d37a9518242fd7f0f5be1b", hash)
}

func bitcoinBuildTransactionObserverSigner(ctx context.Context, require *require.Assertions, nodes []*Node, mpc string, mainInputs []*bitcoin.Input, outputs []*bitcoin.Output) (*wire.MsgTx, string, error) {
	psbt, err := bitcoin.BuildPartiallySignedTransaction(mainInputs, outputs, nil, bitcoin.ChainBitcoin)
	require.Nil(err)
	require.Nil(psbt.SanityCheck())
	ps64, _ := psbt.B64Encode()
	require.Equal("cHNidP8BALICAAAAAm0tH3NAsAt/UNHjgdFmHWmGSDk+gWZJFY8WRhu5XTkyAgAAAAAGAAAAbS0fc0CwC39Q0eOB0WYdaYZIOT6BZkkVjxZGG7ldOTIBAAAAAAYAAAACECcAAAAAAAAiACDd2I9aG2Cnol9z8RjL22VsWA4wVKQzQXTMO//SlvZIxaBOAgAAAAAAIgAg3diPWhtgp6Jfc/EYy9tlbFgOMFSkM0F0zDv/0pb2SMUAAAAACVNJR0hBU0hFU0ClFtbSZlNTDgBkOJB3BvQVmi53pwG1BuaAxJX8IVqiRCafvhZJRJwlZBiOW0EozqemgfUCwT6j7DpCXEk/S96AAAEBKyAWAQAAAAAAIgAg3diPWhtgp6Jfc/EYy9tlbFgOMFSkM0F0zDv/0pb2SMUBAwSBAAAAAQV2IQORHB7zlgvnMEWWz6YHOx1lrUO0IaTCchQsx6g2m1EMVqx8IQK/Cn+kt5BaDeWrYKUyJSnhpZHd0e5T34LnUeittL7QjKyTfIKSYyECAh1JnCar2cEfSuyEwP/DwhRTQncYQ8+rBB4Ji4fYXGutVrKSaJNShwABASuQXwEAAAAAACIAIN3Yj1obYKeiX3PxGMvbZWxYDjBUpDNBdMw7/9KW9kjFAQMEgQAAAAEFdiEDkRwe85YL5zBFls+mBzsdZa1DtCGkwnIULMeoNptRDFasfCECvwp/pLeQWg3lq2ClMiUp4aWR3dHuU9+C51HorbS+0Iysk3yCkmMhAgIdSZwmq9nBH0rshMD/w8IUU0J3GEPPqwQeCYuH2FxrrVaykmiTUocAAAA=", ps64)
	tx := psbt.UnsignedTx
	require.Equal(psbt.Hash(), tx.TxHash().String())
	require.Equal(int64(10000), tx.TxOut[0].Value)
	require.Equal(int64(151200), tx.TxOut[1].Value)

	ob, _ := hex.DecodeString(testBitcoinKeyObserver)
	observer, _ := btcec.PrivKeyFromBytes(ob)

	for idx := range tx.TxIn {
		pin := psbt.Inputs[idx]
		hash := psbt.SigHash(idx)

		signature := ecdsa.Sign(observer, hash)
		sig := append(signature.Serialize(), byte(bitcoin.SigHashType))
		ss := hex.EncodeToString(sig)
		switch idx {
		case 0:
			require.Equal("3044022055c3fbdc22df48e68423b11610fb4c7652d2c6a2a3615ce0e9ab0605f6914aad02200bcfb77f35438520f034d224f6b01ff0c0e2d08fc371297492604216c39e5fb081", ss)
		case 1:
			require.Equal("30440220626751c1da9d902a1b94591bb5b41947ae6060a0d89624b99806ad39c277250a022056248cc5902b659dc7a7a7fca84eeb75fb948ea2ea982b89419e738ec968934981", ss)
		}

		der, err := ecdsa.ParseDERSignature(sig[:len(sig)-1])
		require.Nil(err)
		require.True(der.Verify(hash, observer.PubKey()))

		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, sig)

		sig = testCMPSign(ctx, require, nodes, mpc, hash, common.CurveSecp256k1ECDSABitcoin)
		_, err = ecdsa.ParseSignature(sig)
		require.Nil(err)
		sig = append(sig, byte(bitcoin.SigHashType))
		der, err = ecdsa.ParseDERSignature(sig[:len(sig)-1])
		require.Nil(err)
		pub, _ := hex.DecodeString(mpc)
		signer, _ := btcutil.NewAddressPubKey(pub, &chaincfg.MainNetParams)
		require.True(der.Verify(hash, signer.PubKey()))

		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, sig)
		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, []byte{})
		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, pin.WitnessScript)
	}

	var rawBuffer bytes.Buffer
	err = psbt.UnsignedTx.BtcEncode(&rawBuffer, wire.ProtocolVersion, wire.BaseEncoding)
	require.Nil(err)
	var signedBuffer bytes.Buffer
	err = tx.BtcEncode(&signedBuffer, wire.ProtocolVersion, wire.WitnessEncoding)
	require.Nil(err)
	signed := hex.EncodeToString(signedBuffer.Bytes())
	raw := hex.EncodeToString(rawBuffer.Bytes())
	require.Contains(signed, raw[8:len(raw)-8])
	logger.Println(signed)

	return tx, raw, nil
}

func TestCMPBitcoinSignHolderSigner(t *testing.T) {
	require := require.New(t)
	ctx, nodes := TestPrepare(require)

	public := TestCMPPrepareKeys(ctx, require, nodes, common.CurveSecp256k1ECDSABitcoin)

	mpc, _ := hex.DecodeString(public)
	wsa, err := bitcoinMultisigWitnessScriptHash(mpc)
	require.Nil(err)
	require.Equal(testBitcoinAddress, wsa.Address)
	require.Equal("2103911c1ef3960be7304596cfa6073b1d65ad43b421a4c272142cc7a8369b510c56ac7c2102bf0a7fa4b7905a0de5ab60a5322529e1a591ddd1ee53df82e751e8adb4bed08cac937c8292632102021d499c26abd9c11f4aec84c0ffc3c2145342771843cfab041e098b87d85c6bad56b29268935287", hex.EncodeToString(wsa.Script))
	require.Equal(uint32(6), wsa.Sequence)

	mainInputs := []*bitcoin.Input{{
		TransactionHash: "b229e760f06117a03aee01fe9b6f77313450317efcd5ec57ad3d2b3f4f6eed57",
		Index:           0,
		Satoshi:         100000,
		Script:          wsa.Script,
		Sequence:        wsa.Sequence,
		RouteBackup:     false,
	}}
	outputs := []*bitcoin.Output{{
		Address: testBitcoinAddress,
		Satoshi: 100000,
	}}
	hash, raw, err := bitcoinBuildTransactionHolderSigner(ctx, require, nodes, public, mainInputs, outputs)
	require.Nil(err)
	require.Equal("f3e8c4d44c898d582a52dbbd995519b2e089039da95a7e94effbc1d6dc22c36c", hash)
	require.Equal("020000000157ed6e4f3f2b3dad57ecd5fc7e31503431776f9bfe01ee3aa01761f060e729b20000000000ffffffff01a086010000000000220020ddd88f5a1b60a7a25f73f118cbdb656c580e3054a4334174cc3bffd296f648c500000000", raw)
}

func bitcoinBuildTransactionHolderSigner(ctx context.Context, require *require.Assertions, nodes []*Node, mpc string, mainInputs []*bitcoin.Input, outputs []*bitcoin.Output) (string, string, error) {
	psbt, err := bitcoin.BuildPartiallySignedTransaction(mainInputs, outputs, nil, bitcoin.ChainBitcoin)
	require.Nil(err)
	require.Nil(psbt.SanityCheck())
	ps64, _ := psbt.B64Encode()
	require.Equal("cHNidP8BAF4CAAAAAVftbk8/Kz2tV+zV/H4xUDQxd2+b/gHuOqAXYfBg5ymyAAAAAAD/////AaCGAQAAAAAAIgAg3diPWhtgp6Jfc/EYy9tlbFgOMFSkM0F0zDv/0pb2SMUAAAAACVNJR0hBU0hFUyDyyl91hPeAC57lGViGAVxzDdxKEKl1cIdrd1O9WD8MiwABASughgEAAAAAACIAIN3Yj1obYKeiX3PxGMvbZWxYDjBUpDNBdMw7/9KW9kjFAQMEgQAAAAEFdiEDkRwe85YL5zBFls+mBzsdZa1DtCGkwnIULMeoNptRDFasfCECvwp/pLeQWg3lq2ClMiUp4aWR3dHuU9+C51HorbS+0Iysk3yCkmMhAgIdSZwmq9nBH0rshMD/w8IUU0J3GEPPqwQeCYuH2FxrrVaykmiTUocAAA==", ps64)
	tx := psbt.UnsignedTx
	require.Equal(psbt.Hash(), tx.TxHash().String())
	require.Equal(int64(100000), tx.TxOut[0].Value)

	hb, _ := hex.DecodeString(testBitcoinKeyHolder)
	holder, _ := btcec.PrivKeyFromBytes(hb)

	for idx := range tx.TxIn {
		pin := psbt.Inputs[idx]
		hash := psbt.SigHash(idx)

		sig := testCMPSign(ctx, require, nodes, mpc, hash, common.CurveSecp256k1ECDSABitcoin)
		_, err = ecdsa.ParseSignature(sig)
		require.Nil(err)
		sig = append(sig, byte(bitcoin.SigHashType))
		der, err := ecdsa.ParseDERSignature(sig[:len(sig)-1])
		require.Nil(err)
		pub, _ := hex.DecodeString(mpc)
		signer, _ := btcutil.NewAddressPubKey(pub, &chaincfg.MainNetParams)
		require.True(der.Verify(hash, signer.PubKey()))

		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, []byte{})
		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, sig)

		signature := ecdsa.Sign(holder, hash)
		sig = append(signature.Serialize(), byte(bitcoin.SigHashType))
		ss := hex.EncodeToString(sig)
		require.Equal("30440220112ad744e23cc6a2409425321d0c344e9dbb584c200169c5bfbb4e7277758ccd02200fbea05953ef7969d95c7ed63d3b335a0ddff19922d4be293b6bc7acd89f924281", ss)
		der, err = ecdsa.ParseDERSignature(sig[:len(sig)-1])
		require.Nil(err)
		require.True(der.Verify(hash, holder.PubKey()))
		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, sig)

		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, pin.WitnessScript)
	}

	var rawBuffer bytes.Buffer
	err = psbt.UnsignedTx.BtcEncode(&rawBuffer, wire.ProtocolVersion, wire.BaseEncoding)
	require.Nil(err)
	var signedBuffer bytes.Buffer
	err = tx.BtcEncode(&signedBuffer, wire.ProtocolVersion, wire.WitnessEncoding)
	require.Nil(err)
	signed := hex.EncodeToString(signedBuffer.Bytes())
	raw := hex.EncodeToString(rawBuffer.Bytes())
	require.Contains(signed, raw[8:len(raw)-8])
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
	return bitcoin.BuildWitnessScriptAccount(holder, signer, observer, time.Minute*60, bitcoin.ChainBitcoin)
}
