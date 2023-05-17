package bitcoin

import (
	"encoding/base64"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/ecdsa"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
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
}

func TestBitcoinAddress(t *testing.T) {
	require := require.New(t)
	addr, err := ParseAddress("bc1q7wqpsk0ckquckd7v0e38uqkscjh7v0ncelqpz459hueet5uknamqrlgp2d", ChainBitcoin)
	require.Nil(err)
	require.Equal("bc1q7wqpsk0ckquckd7v0e38uqkscjh7v0ncelqpz459hueet5uknamqrlgp2d", addr)
	addr, err = ParseAddress("bc1q7wqpsk0ckquckd7v0e38uqkscjh7v0ncelqpz459hueet5uknamqrlgp2d", ChainLitecoin)
	require.NotNil(err)
	require.Equal("", addr)

	addr, err = ParseAddress("ltc1qhlq0h89m6n0a099kr55qssaz2u82xj5u66taffekch2dfh6vf7escf4l0k", ChainLitecoin)
	require.Nil(err)
	require.Equal("ltc1qhlq0h89m6n0a099kr55qssaz2u82xj5u66taffekch2dfh6vf7escf4l0k", addr)
	addr, err = ParseAddress("ltc1qhlq0h89m6n0a099kr55qssaz2u82xj5u66taffekch2dfh6vf7escf4l0k", ChainBitcoin)
	require.NotNil(err)
	require.Equal("", addr)
}
