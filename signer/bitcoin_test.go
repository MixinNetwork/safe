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
	"github.com/test-go/testify/require"
)

const (
	testBitcoinAddress     = "bc1qmhvg7ksmvzn6yhmn7yvvhkm9d3vquvz55se5zaxv80la99hkfrzs7dqupy"
	testBitcoinKeyHolder   = "52250bb9b9edc5d54466182778a6470a5ee34033c215c92dd250b9c2ce543556"
	testBitcoinKeyObserver = "35fe01cbdc659810854615319b51899b78966c513f0515ee9d77ef6016090221"
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
		TransactionHash: "22c6ce7dbdb455fe020255fe326f216cb21205e25bedc1d23ccc0c06718861ba",
		Index:           0,
		Satoshi:         100000,
		Script:          wsa.Script,
		Sequence:        wsa.Sequence,
		RouteBackup:     true,
	}}
	feeInputs := []*bitcoin.Input{{
		TransactionHash: "22c6ce7dbdb455fe020255fe326f216cb21205e25bedc1d23ccc0c06718861ba",
		Index:           1,
		Satoshi:         86560,
		Script:          wsa.Script,
		Sequence:        wsa.Sequence,
		RouteBackup:     true,
	}}
	outputs := []*bitcoin.Output{{
		Address: testBitcoinAddress,
		Satoshi: 10000,
	}}
	hash, raw, err := bitcoinBuildTransactionObserverSigner(ctx, require, nodes, public, mainInputs, feeInputs, outputs, 60)
	require.Nil(err)
	require.Equal("32395db91b46168f154966813e394886691d66d181e3d1507f0bb040731f2d6d", hash)
	require.Equal("0200000002ba618871060ccc3cd2c1ed5be20512b26c216f32fe550202fe55b4bd7dcec622000000000006000000ba618871060ccc3cd2c1ed5be20512b26c216f32fe550202fe55b4bd7dcec622010000000006000000031027000000000000220020ddd88f5a1b60a7a25f73f118cbdb656c580e3054a4334174cc3bffd296f648c5905f010000000000220020ddd88f5a1b60a7a25f73f118cbdb656c580e3054a4334174cc3bffd296f648c52016010000000000220020ddd88f5a1b60a7a25f73f118cbdb656c580e3054a4334174cc3bffd296f648c500000000", raw)
}

func bitcoinBuildTransactionObserverSigner(ctx context.Context, require *require.Assertions, nodes []*Node, mpc string, mainInputs, feeInputs []*bitcoin.Input, outputs []*bitcoin.Output, fvb int64) (string, string, error) {
	psbt, err := bitcoin.BuildPartiallySignedTransaction(mainInputs, feeInputs, outputs, fvb, nil, bitcoin.ChainBitcoin)
	require.Nil(err)
	require.Nil(psbt.Packet.SanityCheck())
	ps64, _ := psbt.Packet.B64Encode()
	require.Equal("cHNidP8BAN0CAAAAArphiHEGDMw80sHtW+IFErJsIW8y/lUCAv5VtL19zsYiAAAAAAAGAAAAumGIcQYMzDzSwe1b4gUSsmwhbzL+VQIC/lW0vX3OxiIBAAAAAAYAAAADECcAAAAAAAAiACDd2I9aG2Cnol9z8RjL22VsWA4wVKQzQXTMO//SlvZIxZBfAQAAAAAAIgAg3diPWhtgp6Jfc/EYy9tlbFgOMFSkM0F0zDv/0pb2SMUgFgEAAAAAACIAIN3Yj1obYKeiX3PxGMvbZWxYDjBUpDNBdMw7/9KW9kjFAAAAAAlTSUdIQVNIRVNAU2fKwtfdQhHYX3fHCAMJqbJb6RWPfTRya2RmRwsghjLX27937L4F/96DpNuiwEND81cP5XKQ9M4JMNHoiCNP8QABASughgEAAAAAACIAIN3Yj1obYKeiX3PxGMvbZWxYDjBUpDNBdMw7/9KW9kjFAQMEAQAAAAEFdiEDkRwe85YL5zBFls+mBzsdZa1DtCGkwnIULMeoNptRDFasfCECvwp/pLeQWg3lq2ClMiUp4aWR3dHuU9+C51HorbS+0Iysk3yCkmMhAgIdSZwmq9nBH0rshMD/w8IUU0J3GEPPqwQeCYuH2FxrrVaykmiTUocAAQErIFIBAAAAAAAiACDd2I9aG2Cnol9z8RjL22VsWA4wVKQzQXTMO//SlvZIxQEDBAEAAAABBXYhA5EcHvOWC+cwRZbPpgc7HWWtQ7QhpMJyFCzHqDabUQxWrHwhAr8Kf6S3kFoN5atgpTIlKeGlkd3R7lPfgudR6K20vtCMrJN8gpJjIQICHUmcJqvZwR9K7ITA/8PCFFNCdxhDz6sEHgmLh9hca61WspJok1KHAAAAAA==", ps64)
	tx := psbt.Packet.UnsignedTx
	require.Equal(psbt.Hash, tx.TxHash().String())
	require.Equal(int64(10000), tx.TxOut[0].Value)
	require.Equal(int64(90000), tx.TxOut[1].Value)
	require.Equal(int64(71200), tx.TxOut[2].Value)

	ob, _ := hex.DecodeString(testBitcoinKeyObserver)
	observer, _ := btcec.PrivKeyFromBytes(ob)

	for idx := range tx.TxIn {
		pin := psbt.Packet.Inputs[idx]
		hash := psbt.SigHash(idx)

		signature := ecdsa.Sign(observer, hash)
		sig := append(signature.Serialize(), byte(txscript.SigHashAll))
		ss := hex.EncodeToString(sig)
		switch idx {
		case 0:
			require.Equal("3045022100dc9166fc4ee6b6cb29237c75ed30c054a0596995d0b38aa6950f5fbcf73d3bca0220130c2f1d1b730542ac3a5ca2c513f3e85e0ee62a0fc445ff4547fefd496d319601", ss)
		case 1:
			require.Equal("3045022100e7f37af73562a847092f8a4ab90f217f417171ed6efe4f98f1490cb6cc40551c022069de05e73a36ab444502ff4917dd529f226e9a0d1758c686930e409fd5fa7ae401", ss)
		}

		der, err := ecdsa.ParseDERSignature(sig[:len(sig)-1])
		require.Nil(err)
		require.True(der.Verify(hash, observer.PubKey()))

		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, sig)

		sig = testCMPSign(ctx, require, nodes, mpc, hash, common.CurveSecp256k1ECDSABitcoin)
		_, err = ecdsa.ParseSignature(sig)
		require.Nil(err)
		sig = append(sig, byte(txscript.SigHashAll))
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
	err = psbt.Packet.UnsignedTx.BtcEncode(&rawBuffer, wire.ProtocolVersion, wire.BaseEncoding)
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
	feeInputs := []*bitcoin.Input{{
		TransactionHash: "f9245cbf69710c9cb77b81485a31bc3201798b14b55dfd0d78257c9829c61994",
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
	hash, raw, err := bitcoinBuildTransactionHolderSigner(ctx, require, nodes, public, mainInputs, feeInputs, outputs, 60)
	require.Nil(err)
	require.Equal("22c6ce7dbdb455fe020255fe326f216cb21205e25bedc1d23ccc0c06718861ba", hash)
	require.Equal("020000000257ed6e4f3f2b3dad57ecd5fc7e31503431776f9bfe01ee3aa01761f060e729b20000000000ffffffff9419c629987c25780dfd5db5148b790132bc315a48817bb79c0c7169bf5c24f90000000000ffffffff02a086010000000000220020ddd88f5a1b60a7a25f73f118cbdb656c580e3054a4334174cc3bffd296f648c52052010000000000220020ddd88f5a1b60a7a25f73f118cbdb656c580e3054a4334174cc3bffd296f648c500000000", raw)
}

func bitcoinBuildTransactionHolderSigner(ctx context.Context, require *require.Assertions, nodes []*Node, mpc string, mainInputs, feeInputs []*bitcoin.Input, outputs []*bitcoin.Output, fvb int64) (string, string, error) {
	psbt, err := bitcoin.BuildPartiallySignedTransaction(mainInputs, feeInputs, outputs, fvb, nil, bitcoin.ChainBitcoin)
	require.Nil(err)
	require.Nil(psbt.Packet.SanityCheck())
	ps64, _ := psbt.Packet.B64Encode()
	require.Equal("cHNidP8BALICAAAAAlftbk8/Kz2tV+zV/H4xUDQxd2+b/gHuOqAXYfBg5ymyAAAAAAD/////lBnGKZh8JXgN/V21FIt5ATK8MVpIgXu3nAxxab9cJPkAAAAAAP////8CoIYBAAAAAAAiACDd2I9aG2Cnol9z8RjL22VsWA4wVKQzQXTMO//SlvZIxSBSAQAAAAAAIgAg3diPWhtgp6Jfc/EYy9tlbFgOMFSkM0F0zDv/0pb2SMUAAAAACVNJR0hBU0hFU0A3qoQi+FPu653gEYYQqkADAeLHO4FOPMi1wnC+g/iYajWa7qrwpYU3wq86eliTpc8yUoBJRVGO3t2Yv+Hphb/bAAEBK6CGAQAAAAAAIgAg3diPWhtgp6Jfc/EYy9tlbFgOMFSkM0F0zDv/0pb2SMUBAwQBAAAAAQV2IQORHB7zlgvnMEWWz6YHOx1lrUO0IaTCchQsx6g2m1EMVqx8IQK/Cn+kt5BaDeWrYKUyJSnhpZHd0e5T34LnUeittL7QjKyTfIKSYyECAh1JnCar2cEfSuyEwP/DwhRTQncYQ8+rBB4Ji4fYXGutVrKSaJNShwABASughgEAAAAAACIAIN3Yj1obYKeiX3PxGMvbZWxYDjBUpDNBdMw7/9KW9kjFAQMEAQAAAAEFdiEDkRwe85YL5zBFls+mBzsdZa1DtCGkwnIULMeoNptRDFasfCECvwp/pLeQWg3lq2ClMiUp4aWR3dHuU9+C51HorbS+0Iysk3yCkmMhAgIdSZwmq9nBH0rshMD/w8IUU0J3GEPPqwQeCYuH2FxrrVaykmiTUocAAAA=", ps64)
	tx := psbt.Packet.UnsignedTx
	require.Equal(psbt.Hash, tx.TxHash().String())
	require.Equal(int64(100000), tx.TxOut[0].Value)
	require.Equal(int64(86560), tx.TxOut[1].Value)

	hb, _ := hex.DecodeString(testBitcoinKeyHolder)
	holder, _ := btcec.PrivKeyFromBytes(hb)

	for idx := range tx.TxIn {
		pin := psbt.Packet.Inputs[idx]
		hash := psbt.SigHash(idx)

		sig := testCMPSign(ctx, require, nodes, mpc, hash, common.CurveSecp256k1ECDSABitcoin)
		_, err = ecdsa.ParseSignature(sig)
		require.Nil(err)
		sig = append(sig, byte(txscript.SigHashAll))
		der, err := ecdsa.ParseDERSignature(sig[:len(sig)-1])
		require.Nil(err)
		pub, _ := hex.DecodeString(mpc)
		signer, _ := btcutil.NewAddressPubKey(pub, &chaincfg.MainNetParams)
		require.True(der.Verify(hash, signer.PubKey()))

		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, []byte{})
		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, sig)

		signature := ecdsa.Sign(holder, hash)
		sig = append(signature.Serialize(), byte(txscript.SigHashAll))
		ss := hex.EncodeToString(sig)
		switch idx {
		case 0:
			require.Equal("3045022100edfd6db9896f3087ebbd881be18e0dd7849599ebd6a37eb910c0619d6abb25270220127d56b7a318a1504c9fa7bce1a7afa4f6c1ae54964c373319fa2bf99f5ac5e401", ss)
		case 1:
			require.Equal("30440220320c9fb32bc883210ac85f18a0d3dfc91e607900702d4d673938f16229cb0893022067b13b03cabf5b3dd43e4fc0d2a3c679622d5db8f56331ce0cc758f843b6f75f01", ss)
		}
		der, err = ecdsa.ParseDERSignature(sig[:len(sig)-1])
		require.Nil(err)
		require.True(der.Verify(hash, holder.PubKey()))
		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, sig)

		tx.TxIn[idx].Witness = append(tx.TxIn[idx].Witness, pin.WitnessScript)
	}

	var rawBuffer bytes.Buffer
	err = psbt.Packet.UnsignedTx.BtcEncode(&rawBuffer, wire.ProtocolVersion, wire.BaseEncoding)
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
