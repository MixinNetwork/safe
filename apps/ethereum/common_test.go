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
