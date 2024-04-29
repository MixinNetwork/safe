package abi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const testReceiverAddress = "0x9d04735aaEB73535672200950fA77C2dFC86eB21"

func TestAssetAddress(t *testing.T) {
	require := require.New(t)
	InitFactoryContractAddress("0x4D17777E0AC12C6a0d4DEF1204278cFEAe142a1E")
	suffix := " XIN2SB4YVNyxv6sYmZfmggidFGx73VVjiqMnefVFRzwFAPQSgc5NyGxPeXP5D4hSeJSrioE117oke4TwT3DhN2VrdLr9q4Fv"

	assetId := "c6d0c728-2624-429b-8e0d-d9d19b6592fa"
	symbol := "BTC"
	name := "Bitcoin"
	holder := "51e689b98ad210202182f14089c68ea11925265250ea8580bef29fca89634f00"

	addr := GetFactoryAssetAddress(testReceiverAddress, assetId, symbol, name, holder)
	require.Equal("0x8aB4fA038cfC9BD69b070AD1363c9Ce793FFEE52", addr.String())

	addr = GetFactoryAssetAddress(testReceiverAddress, assetId, symbol+suffix, name+suffix, holder+suffix)
	require.Equal("0x45fA088DB007269bC37FEcE893d485C9AC2848B6", addr.String())
}
