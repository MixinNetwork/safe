package abi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAssetAddress(t *testing.T) {
	require := require.New(t)
	suffix := " XIN2SB4YVNyxv6sYmZfmggidFGx73VVjiqMnefVFRzwFAPQSgc5NyGxPeXP5D4hSeJSrioE117oke4TwT3DhN2VrdLr9q4Fv"

	assetId := "c6d0c728-2624-429b-8e0d-d9d19b6592fa"
	symbol := "BTC"
	name := "Bitcoin"
	holder := "51e689b98ad210202182f14089c68ea11925265250ea8580bef29fca89634f00"
	addr := GetFactoryAssetAddress(assetId, symbol, name, holder)
	require.Equal("0x57bdD7e390F31Dac25021CF8c28461F51337c242", addr.String())

	addr = GetFactoryAssetAddress(assetId, symbol+suffix, name+suffix, holder+suffix)
	require.Equal("0xb27B9aC25E80D5834CC62FcA876BdC645A59D5F1", addr.String())
}
