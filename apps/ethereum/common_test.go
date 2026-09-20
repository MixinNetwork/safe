package ethereum

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchDepositTransfer(t *testing.T) {
	require := require.New(t)

	hash := "0x1111111111111111111111111111111111111111111111111111111111111111"
	token := "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	receiver := "0x2222222222222222222222222222222222222222"
	transfer := &Transfer{
		Hash:         hash,
		Index:        42,
		TokenAddress: token,
		Receiver:     receiver,
		Value:        big.NewInt(100000000),
	}
	amount := NormallizeAmount(transfer.Value, 6)

	// the exact claimed deposit matches
	require.True(matchDepositTransfer(transfer, hash, token, receiver, 42, amount, 6))

	// the hash comparison is case-insensitive
	require.True(matchDepositTransfer(transfer, "0X1111111111111111111111111111111111111111111111111111111111111111", token, receiver, 42, amount, 6))

	// the same transfer claimed under another transaction hash of the
	// same block must be rejected, otherwise it is credited twice
	other := *transfer
	other.Hash = "0x3333333333333333333333333333333333333333333333333333333333333333"
	require.False(matchDepositTransfer(&other, hash, token, receiver, 42, amount, 6))

	// any other field mismatch must be rejected
	wrongIndex := *transfer
	wrongIndex.Index = 43
	require.False(matchDepositTransfer(&wrongIndex, hash, token, receiver, 42, amount, 6))

	wrongToken := *transfer
	wrongToken.TokenAddress = "0x4444444444444444444444444444444444444444"
	require.False(matchDepositTransfer(&wrongToken, hash, token, receiver, 42, amount, 6))

	wrongReceiver := *transfer
	wrongReceiver.Receiver = "0x5555555555555555555555555555555555555555"
	require.False(matchDepositTransfer(&wrongReceiver, hash, token, receiver, 42, amount, 6))

	wrongAmount := *transfer
	wrongAmount.Value = big.NewInt(100000001)
	require.False(matchDepositTransfer(&wrongAmount, hash, token, receiver, 42, amount, 6))
}

func TestLoopCallsIgnoresInheritedDelegateCallValue(t *testing.T) {
	require := require.New(t)

	safe := "0x1111111111111111111111111111111111111111"
	receiver := "0x2222222222222222222222222222222222222222"
	attacker := "0x3333333333333333333333333333333333333333"
	oneEther := "0xde0b6b3a7640000"

	// Models a safe withdrawal of 1 ETH to an attacker contract whose
	// fallback delegatecalls back to the safe. The DELEGATECALL frame
	// reports the inherited 1 ETH although no ether moves, and must not
	// produce a phantom deposit to the safe.
	trace := &RPCTransactionCallTrace{
		Type: "CALL", From: attacker, To: safe, Value: "0x0",
		Calls: []*RPCTransactionCallTrace{
			{Type: "CALL", From: safe, To: receiver, Value: oneEther},
			{Type: "DELEGATECALL", From: receiver, To: safe, Value: oneEther},
			{Type: "CALLCODE", From: receiver, To: safe, Value: oneEther},
			{Type: "STATICCALL", From: receiver, To: safe, Value: oneEther},
			{Type: "CALL", From: receiver, To: safe, Value: oneEther, Error: "execution reverted"},
			{Type: "DELEGATECALL", From: safe, To: attacker, Value: "0x0",
				Calls: []*RPCTransactionCallTrace{
					// a call nested below a delegatecall frame is a real
					// value transfer and must still be visited
					{Type: "CALL", From: attacker, To: safe, Value: oneEther},
				}},
		},
	}

	transfers, end := LoopCalls(ChainEthereum, "asset-id", "tx-hash", trace, 0)
	require.Len(transfers, 2)
	require.Equal(int64(8), end)

	real := transfers[0]
	require.Equal(int64(1), real.Index)
	require.Equal(safe, real.Sender)
	require.Equal(receiver, real.Receiver)
	require.Equal(big.NewInt(1_000_000_000_000_000_000), real.Value)

	nested := transfers[1]
	require.Equal(int64(7), nested.Index)
	require.Equal(attacker, nested.Sender)
	require.Equal(safe, nested.Receiver)
	require.Equal(EthereumEmptyAddress, nested.TokenAddress)
}
