package ethereum

import (
	"math"
	"math/big"
	"os"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// These tests exercise real mainnet transactions through live public RPC
// endpoints. Set ETHEREUMRPC or POLYGONRPC to a full node with the debug
// namespace enabled to override the default public endpoints.
//
// The two delegatecall anchor transactions below contain DELEGATECALL
// frames that report the value inherited from their parent call frame,
// although no ether moves for these frames. The traces were fetched from
// the respective mainnets when the tests were written.
const (
	// Ethereum mainnet block 25867831: root CALL of 0.305 ETH to a proxy,
	// which DELEGATECALLs to its implementation with the same value, then
	// performs eight real payout CALLs.
	mainnetDelegateCallTxEthereum = "0x6868fc4dae9aa27233b97261a0fc702b7773f245cdf59fd265af5695b9f63fb2"
	// Polygon block 92922900: two value-bearing DELEGATECALL frames.
	mainnetDelegateCallTxPolygon = "0xd9b99e3e7c303f53432002f789ba5f1e1c2d5b7603caec8a8ce1afc93f346894"
	mainnetDelegateCallTxBlock   = int64(92922900)
)

type mainnetExpectedTransfer struct {
	receiver string
	valueHex string
	index    int64
}

func mainnetRPC(env, fallback string) string {
	if rpc := os.Getenv(env); rpc != "" {
		return rpc
	}
	return fallback
}

func requireMainnetTransfers(t *testing.T, transfers []*Transfer, hash string, expected []mainnetExpectedTransfer, phantoms ...string) {
	t.Helper()
	require.Len(t, transfers, len(expected))
	for i, exp := range expected {
		require.Equal(t, exp.index, transfers[i].Index, i)
		require.Equal(t, ethcommon.HexToAddress(exp.receiver).Hex(), transfers[i].Receiver, i)
		value, ok := new(big.Int).SetString(exp.valueHex, 16)
		require.True(t, ok, exp.valueHex)
		require.Zero(t, transfers[i].Value.Cmp(value), i)
		require.Equal(t, hash, transfers[i].Hash, i)
		require.Equal(t, EthereumEmptyAddress, transfers[i].TokenAddress, i)
	}
	for _, phantom := range phantoms {
		for _, transfer := range transfers {
			require.NotEqual(t, ethcommon.HexToAddress(phantom).Hex(), transfer.Receiver)
		}
	}
}

func TestLoopCallsRealEthereumDelegateCallInheritance(t *testing.T) {
	rpc := mainnetRPC("ETHEREUMRPC", "https://eth.drpc.org")
	trace, err := RPCDebugTraceTransactionByHash(rpc, mainnetDelegateCallTxEthereum)
	require.NoError(t, err)
	require.Equal(t, "CALL", trace.Type)

	transfers, _ := LoopCalls(ChainEthereum, "ethereum", mainnetDelegateCallTxEthereum, trace, 0)
	requireMainnetTransfers(t, transfers, mainnetDelegateCallTxEthereum, []mainnetExpectedTransfer{
		{"0x09c30cdcdd971423cb3ba757a47d56c35d06d818", "43c256737a88000", 0},
		{"0x1e67ca426a22307336684f81e33ed52950cdeaca", "5795ba376a5c00", 2},
		{"0xc5019d7ac0b2b7c67fd8f151386a350128954522", "5699247d77ec00", 3},
		{"0xe47bfc5d42ab63060e3f723a22c8ba29b20ade3b", "71c4e4f462b000", 4},
		{"0x6e310d66ca7b9de2772fbc6c6afa4f144b2a9a1b", "55ac257b220400", 5},
		{"0x8c058d81f32d8f3b01c7b46c7855df50db6bf0c4", "39da33df79dc00", 6},
		{"0xc33ea33025fa082be3f9ce7377f716e5312d6989", "177e06030667800", 7},
		{"0x3e9df451536ce4358b5a5fd18fda1d2be1f324e7", "bd2be6988a8000", 8},
		{"0x2241475ce828dd54c8ffd6c9909c4d1553c30dea", "579f036ad6b000", 9},
	}, "0x6d28bc0f114e3c629320ee692ede5bdd7155e6fe")
}

func TestLoopCallsRealPolygonDelegateCallInheritance(t *testing.T) {
	rpc := mainnetRPC("POLYGONRPC", "https://polygon.drpc.org")
	trace, err := RPCDebugTraceTransactionByHash(rpc, mainnetDelegateCallTxPolygon)
	require.NoError(t, err)
	require.Equal(t, "CALL", trace.Type)

	transfers, _ := LoopCalls(ChainPolygon, "polygon", mainnetDelegateCallTxPolygon, trace, 0)
	requireMainnetTransfers(t, transfers, mainnetDelegateCallTxPolygon, []mainnetExpectedTransfer{
		{"0x3a0b42ce6166abb05d30ddf12e726c95a83d7a16", "4502608ae0652203", 0},
		{"0xfb7c744da69aef11dfb54f31d9db12a3b086b025", "4502608ae0652203", 1},
		{"0xf2446da67fe63efcd0179275937800f0a3828616", "a2db1fc3fbfbcf", 3},
		{"0x97ccdbea4632140639ad5ea9b944aa034eb15fd4", "445f856b1c692634", 5},
		{"0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270", "445f856b1c692634", 6},
	},
		"0x7ac070f096c6e20931c3dc54f927446be232618b",
		"0x3e5c63644e683549055b9be8653de26e0b4cd36e",
	)
}

// VerifyDeposit additionally cross-checks the receiver balance change
// between the deposit block and its parent. This real clean transfer
// passes that check: the receiver's balance delta equals the deposit.
//
// Polygon tx 0x4b1552672741d89fe480b5e2ae8a50597549aa7131240542f8db5025bb8e2ecf
// in block 92922843 transferred 0.15 POL to
// 0xa17efcff026e03d070549f674ab51d472f9e48ca, whose balance increased by
// exactly the transfer amount in that block.
func TestVerifyDepositRealCleanPolygonTransfer(t *testing.T) {
	rpc := mainnetRPC("POLYGONRPC", "https://polygon.drpc.org")
	const (
		hash      = "0x4b1552672741d89fe480b5e2ae8a50597549aa7131240542f8db5025bb8e2ecf"
		receiver  = "0xa17efcff026e03d070549f674ab51d472f9e48ca"
		amountHex = "214e8348c4f0000" // 0.15 POL
	)
	amount, ok := new(big.Int).SetString(amountHex, 16)
	require.True(t, ok)
	destination := ethcommon.HexToAddress(receiver).Hex()

	transfer, _, err := VerifyDeposit(
		t.Context(), ChainPolygon, rpc, hash, "polygon",
		EthereumEmptyAddress, destination, ValuePrecision, 0, amount,
	)
	require.NoError(t, err)
	require.NotNil(t, transfer)
	require.Equal(t, destination, transfer.Receiver)
	require.Zero(t, transfer.Value.Cmp(amount))
}

// The same balance consistency check rejects this real and legitimate
// transfer: the receiver's balance did not increase by the deposit
// amount, because it paid out the received funds in the very same
// transaction. This demonstrates that the strict per-deposit equality
// cannot tell a fabricated transfer from a real deposit to an address
// whose balance moves for other reasons in the same block.
//
// Ethereum mainnet tx 0x6868fc4dae9aa27233b97261a0fc702b7773f245cdf59fd265af5695b9f63fb2
// in block 25867831 transferred 0.30516 ETH to
// 0x09c30cdcdd971423cb3ba757a47d56c35d06d818, whose balance was zero
// both before and after the block.
func TestVerifyDepositRealTransferWithSameBlockOutflowError(t *testing.T) {
	rpc := mainnetRPC("ETHEREUMRPC", "https://eth.drpc.org")
	const amountHex = "43c256737a88000" // 0.30516 ETH
	amount, ok := new(big.Int).SetString(amountHex, 16)
	require.True(t, ok)
	destination := ethcommon.HexToAddress("0x09c30cdcdd971423cb3ba757a47d56c35d06d818").Hex()

	_, _, err := VerifyDeposit(
		t.Context(), ChainEthereum, rpc, mainnetDelegateCallTxEthereum, "ethereum",
		EthereumEmptyAddress, destination, ValuePrecision, 0, amount,
	)
	require.ErrorContains(t, err, "inconsistent")
}

// The balance consistency check must compare the on-chain balance delta
// against the raw transferred value, not the precision-normalized
// deposit amount. Mixin amount rounding discards the sub-precision dust
// from the credited amount, while the balance delta includes it, so any
// deposit of a high precision asset with dust below the rounding
// quantum would otherwise be rejected as inconsistent.
//
// This real Polygon deposit transferred 1.1e-8 POL, one tenth of which
// is sub-precision dust: the credited amount is rounded down to 1e-8
// POL, while the receiver balance increased by the full raw amount.
//
// Polygon tx 0x8375f2b2964b74c6313225887dc5e7f5006e04b0f5cd139342d01e54360d9900
// in block 77713052 transferred 11000000000 wei to
// 0x346607eb15821a4e194628444f3705c26c8e6ebe, whose balance increased
// by exactly that raw amount in the block.
func TestVerifyDepositBalanceChangeComparesRawTransferValue(t *testing.T) {
	rpc := mainnetRPC("POLYGONRPC", "https://polygon.drpc.org")
	const rawValue = 11_000_000_000
	claimed := NormallizeAmount(big.NewInt(rawValue), ValuePrecision)
	require.Equal(t, "10000000000", claimed.String()) // dust rounded away
	destination := ethcommon.HexToAddress("0x346607eb15821a4e194628444f3705c26c8e6ebe").Hex()

	transfer, etx, err := VerifyDeposit(
		t.Context(), ChainPolygon, rpc,
		"0x8375f2b2964b74c6313225887dc5e7f5006e04b0f5cd139342d01e54360d9900",
		"polygon", EthereumEmptyAddress, destination, ValuePrecision, 0, claimed,
	)
	require.NoError(t, err)
	require.NotNil(t, transfer)
	require.Equal(t, destination, transfer.Receiver)
	require.Equal(t, int64(rawValue), transfer.Value.Int64())
	require.Equal(t, uint64(77713052), etx.BlockHeight)
}

func TestGetERC20TransferLogFromBlockRealPolygonBlock(t *testing.T) {
	rpc := mainnetRPC("POLYGONRPC", "https://polygon.drpc.org")
	transfers, err := GetERC20TransferLogFromBlock(t.Context(), rpc, ChainPolygon, mainnetDelegateCallTxBlock)
	require.NoError(t, err)
	require.NotEmpty(t, transfers)

	var weth *Transfer
	wethAddress := ethcommon.HexToAddress("0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270").Hex()
	for _, transfer := range transfers {
		require.NotEmpty(t, transfer.Sender)
		require.NotEmpty(t, transfer.Receiver)
		require.NotNil(t, transfer.Value)
		if transfer.Hash == mainnetDelegateCallTxPolygon &&
			transfer.TokenAddress == wethAddress && weth == nil {
			weth = transfer
		}
	}
	// the block contains real ERC20 transfers, e.g. this WETH transfer by
	// the delegatecall anchor transaction above, with the exact values
	// recorded from the Polygon mainnet block
	require.NotNil(t, weth)
	require.Equal(t, int64(math.MaxInt32)+876, weth.Index)
	require.Equal(t, "4926803212451259956", weth.Value.String())
}
