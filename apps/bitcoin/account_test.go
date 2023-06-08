package bitcoin

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/MixinNetwork/multi-party-sig/pkg/ecdsa"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/test-go/testify/require"
)

func TestBitcoinCLI(t *testing.T) {
	require := require.New(t)

	msg := "mixin safe"
	pub := "02221eebc257e4789e3893292e78c19d5feb7788397d511afb3ffb14561ade500a"
	sig := "H3RKBE7bK/BoKoupbB7BC8fKeesHst3tLhfhNSkAPZ8XZuB3nE8YJRPx/6ZPI7PN9fsq2PrnfpETCEoLA8PHAfY="

	err := VerifyHolderKey(pub)
	require.Nil(err)

	s, err := base64.StdEncoding.DecodeString(sig)
	require.Nil(err)
	es, err := ecdsa.ParseSignature(curve.Secp256k1{}, s)
	require.Nil(err)

	s = es.SerializeDER()

	messageHash := HashMessageForSignature(msg, ChainBitcoin)
	err = VerifySignatureDER(pub, messageHash, s)
	require.Nil(err)

	// bitcoin-cli --rpcwallet=holder listdescriptors true
	extPriv, err := hdkeychain.NewKeyFromString("xprv9s21ZrQH143K4NMg6FdKfSHPJN9W642rDck71dJ2j1N4SFePwJjkNm1xU3FCHUEjR9M4ZLCDKC6DonAyNhwg6NNhCoJFojRBeFzPwcQXTMS")
	require.Nil(err)
	require.True(extPriv.IsPrivate())
	require.True(extPriv.IsForNet(&chaincfg.MainNetParams))
	require.Equal("xprv9s21ZrQH143K4NMg6FdKfSHPJN9W642rDck71dJ2j1N4SFePwJjkNm1xU3FCHUEjR9M4ZLCDKC6DonAyNhwg6NNhCoJFojRBeFzPwcQXTMS", extPriv.String())
	require.Equal(netConfig(ChainBitcoin).HDPrivateKeyID[:], extPriv.Version())
	require.Equal(byte(0x0), extPriv.Depth())
	require.Equal(uint32(0x0), extPriv.ParentFingerprint())
	require.Equal(uint32(0x0), extPriv.ChildIndex())
	require.Equal([]byte{0xe8, 0xe, 0x10, 0x47, 0x2e, 0xce, 0x36, 0x5a, 0x31, 0x89, 0xbc, 0x28, 0x59, 0x46, 0xc8, 0xce, 0x5a, 0x1d, 0xe0, 0x1c, 0x48, 0x5a, 0x90, 0xc7, 0x93, 0x1f, 0xc3, 0xe, 0x10, 0x47, 0xe4, 0x97}, extPriv.ChainCode())

	// bitcoin-cli --rpcwallet=holder getaddressinfo 1DdhSdxiLepsH2YuiVxt8n85UHmWp4qjUt
	extPriv, _ = extPriv.Derive(0x80000000 + 44)
	extPriv, _ = extPriv.Derive(0x80000000)
	extPub, err := extPriv.Neuter()
	require.Nil(err)
	ecPub, _ := extPub.ECPubKey()
	parentFP := btcutil.Hash160(ecPub.SerializeCompressed())[:4]
	require.Equal(uint32(0x1987f5fc), binary.BigEndian.Uint32(parentFP))

	extPriv, _ = extPriv.Derive(0x80000000)
	extPub, err = extPriv.Neuter()
	require.Nil(err)
	require.False(extPub.IsPrivate())
	require.True(extPub.IsForNet(&chaincfg.MainNetParams))
	require.Equal(netConfig(ChainBitcoin).HDPublicKeyID[:], extPub.Version())
	require.Equal(byte(0x3), extPub.Depth())
	require.Equal(binary.BigEndian.Uint32(parentFP), extPub.ParentFingerprint())
	require.Equal(uint32(0x80000000), extPub.ChildIndex())
	require.Equal("xpub6Bqeq5d3McUGMHv6PhMPhCCnJt1JSgRJSYHP9q9uLLUnVh9AESmn8NHAsp5NneVg5orAc6EcTrEfMVTTrei6k3J5YPn8MgmN39aiqmD6wjH", extPub.String())

	extPriv, _ = extPriv.Derive(0)
	extPriv, _ = extPriv.Derive(0)
	apkh, _ := extPriv.Address(&chaincfg.MainNetParams)
	require.Equal("1DdhSdxiLepsH2YuiVxt8n85UHmWp4qjUt", apkh.EncodeAddress())
	ecPub, _ = extPriv.ECPubKey()
	require.Equal("03911c1ef3960be7304596cfa6073b1d65ad43b421a4c272142cc7a8369b510c56", hex.EncodeToString(ecPub.SerializeCompressed()))
	ecPriv, _ := extPriv.ECPrivKey()
	require.Equal("52250bb9b9edc5d54466182778a6470a5ee34033c215c92dd250b9c2ce543556", hex.EncodeToString(ecPriv.Serialize()))
}

func TestBitcoinAddress(t *testing.T) {
	require := require.New(t)
	script, err := ParseAddress("bc1q7wqpsk0ckquckd7v0e38uqkscjh7v0ncelqpz459hueet5uknamqrlgp2d", ChainBitcoin)
	require.Nil(err)
	require.Equal("0020f3801859f8b0398b37cc7e627e02d0c4afe63e78cfc0115685bf3395d3969f76", hex.EncodeToString(script))
	script, err = ParseAddress("bc1q7wqpsk0ckquckd7v0e38uqkscjh7v0ncelqpz459hueet5uknamqrlgp2d", ChainLitecoin)
	require.NotNil(err)
	require.Equal("", hex.EncodeToString(script))

	script, err = ParseAddress("ltc1qhlq0h89m6n0a099kr55qssaz2u82xj5u66taffekch2dfh6vf7escf4l0k", ChainLitecoin)
	require.Nil(err)
	require.Equal("0020bfc0fb9cbbd4dfd794b61d280843a2570ea34a9cd697d4a736c5d4d4df4c4fb3", hex.EncodeToString(script))
	script, err = ParseAddress("ltc1qhlq0h89m6n0a099kr55qssaz2u82xj5u66taffekch2dfh6vf7escf4l0k", ChainBitcoin)
	require.NotNil(err)
	require.Equal("", hex.EncodeToString(script))
}

func TestBitcoinScriptAddress(t *testing.T) {
	require := require.New(t)
	lock := time.Hour * 24 * 90
	holder := "03911c1ef3960be7304596cfa6073b1d65ad43b421a4c272142cc7a8369b510c56"
	signer := "028a010d50f3ba6f17ee313f55a1d06412674f2064616b4642f4eee3cb471eeef5"
	observer := "028628daebf3cb6e902dfb6e605edb28d0d9717526fce2d9e1a66a7e4a58ad6f65"

	wsa, err := BuildWitnessScriptAccount(holder, signer, observer, lock, ChainBitcoin)
	require.Nil(err)
	require.Equal("bc1q2nhm0clwt7qcmnpntetjlzf0tflp2h0zvkczql4v9nmydnt7xm6swx2nnv", wsa.Address)
	require.Equal("2103911c1ef3960be7304596cfa6073b1d65ad43b421a4c272142cc7a8369b510c56ac7c21028a010d50f3ba6f17ee313f55a1d06412674f2064616b4642f4eee3cb471eeef5ac937c82926321028628daebf3cb6e902dfb6e605edb28d0d9717526fce2d9e1a66a7e4a58ad6f65ad02a032b29268935287", hex.EncodeToString(wsa.Script))
}

func TestBitcoinSignature(t *testing.T) {
	require := require.New(t)
	sig, _ := hex.DecodeString("304402206c9adbfea684f9dca42700db018a6aaebbee1f679f553e871351031ccdbff3510220064eeed0c51e0a018b4c275e6585fd81d686c106be1708507a1bd4813affb7a881")
	sig, err := CanonicalSignatureDER(sig)
	require.Nil(err)
	require.Equal("304402206c9adbfea684f9dca42700db018a6aaebbee1f679f553e871351031ccdbff3510220064eeed0c51e0a018b4c275e6585fd81d686c106be1708507a1bd4813affb7a8", hex.EncodeToString(sig))

	sig, _ = hex.DecodeString("304402206c9adbfea684f9dca42700db018a6aaebbee1f679f553e871351031ccdbff3510220064eeed0c51e0a018b4c275e6585fd81d686c106be1708507a1bd4813affb7a88181")
	sig, err = CanonicalSignatureDER(sig)
	require.Nil(err)
	require.Equal("304402206c9adbfea684f9dca42700db018a6aaebbee1f679f553e871351031ccdbff3510220064eeed0c51e0a018b4c275e6585fd81d686c106be1708507a1bd4813affb7a8", hex.EncodeToString(sig))

	sig, _ = hex.DecodeString("304402206c9adbfea684f9dca42700db018a6aaebbee1f679f553e871351031ccdbff3510220064eeed0c51e0a018b4c275e6585fd81d686c106be1708507a1bd4813affb7a8")
	sig, err = CanonicalSignatureDER(sig)
	require.Nil(err)
	require.Equal("304402206c9adbfea684f9dca42700db018a6aaebbee1f679f553e871351031ccdbff3510220064eeed0c51e0a018b4c275e6585fd81d686c106be1708507a1bd4813affb7a8", hex.EncodeToString(sig))

	sig, _ = hex.DecodeString("304402206c9adbfea684f9dca42700db018a6aaebbee1f679f553e871351031ccdbff3510220064eeed0c51e0a018b4c275e6585fd81d686c106be1708507a1bd4813affb7")
	sig, err = CanonicalSignatureDER(sig)
	require.NotNil(err)
	require.Nil(sig)
}
