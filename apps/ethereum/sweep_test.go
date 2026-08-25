package ethereum

import (
	"encoding/hex"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestValidateSweepTransaction(t *testing.T) {
	assert := require.New(t)
	const (
		requestID = "0ca34767-3a70-4a28-afd9-51c9bce4ecf5"
		safe      = "0x1111111111111111111111111111111111111111"
		receiver  = "0x2222222222222222222222222222222222222222"
		token     = "0x3333333333333333333333333333333333333333"
		chainID   = int64(137)
	)
	nonce := big.NewInt(42)
	outputs := []*Output{
		{TokenAddress: EthereumEmptyAddress, Destination: receiver, Amount: big.NewInt(100)},
		{TokenAddress: token, Destination: receiver, Amount: big.NewInt(200)},
	}
	tx, err := CreateMultiSendTransaction(t.Context(), chainID, requestID, safe, outputs, nonce)
	assert.NoError(err)
	expected := SweepValidation{
		SafeAddress:        safe,
		ChainID:            chainID,
		Nonce:              nonce,
		RequestID:          requestID,
		TransactionHash:    tx.TxHash,
		AllowedDestination: receiver,
		Balances: map[string]*big.Int{
			EthereumEmptyAddress: big.NewInt(100),
			token:                big.NewInt(200),
		},
	}

	parsed, err := ValidateSweepTransaction(tx, expected)
	assert.NoError(err)
	assert.Len(parsed, 2)
	assert.Equal(receiver, parsed[0].Destination)

	tests := []struct {
		name   string
		mutate func(*SafeTransaction, *SweepValidation)
	}{
		{
			name: "message substitution",
			mutate: func(candidate *SafeTransaction, validation *SweepValidation) {
				candidate.Message[0] ^= 0xff
				candidate.TxHash = sweepTestHash(requestID, candidate.Message)
				validation.TransactionHash = candidate.TxHash
			},
		},
		{
			name: "wrong safe",
			mutate: func(candidate *SafeTransaction, validation *SweepValidation) {
				candidate.SafeAddress = "0x4444444444444444444444444444444444444444"
				sweepTestSeal(candidate, requestID)
				validation.TransactionHash = candidate.TxHash
			},
		},
		{
			name: "wrong chain",
			mutate: func(candidate *SafeTransaction, validation *SweepValidation) {
				candidate.ChainID++
				sweepTestSeal(candidate, requestID)
				validation.TransactionHash = candidate.TxHash
			},
		},
		{
			name: "wrong nonce",
			mutate: func(candidate *SafeTransaction, validation *SweepValidation) {
				candidate.Nonce.Add(candidate.Nonce, big.NewInt(1))
				sweepTestSeal(candidate, requestID)
				validation.TransactionHash = candidate.TxHash
			},
		},
		{
			name: "nonce outside internal range",
			mutate: func(candidate *SafeTransaction, validation *SweepValidation) {
				candidate.Nonce = new(big.Int).Lsh(big.NewInt(1), 63)
				validation.Nonce = new(big.Int).Set(candidate.Nonce)
				sweepTestSeal(candidate, requestID)
				validation.TransactionHash = candidate.TxHash
			},
		},
		{
			name: "unbound transaction hash",
			mutate: func(candidate *SafeTransaction, validation *SweepValidation) {
				candidate.TxHash = hex.EncodeToString(make([]byte, 32))
				validation.TransactionHash = candidate.TxHash
			},
		},
		{
			name: "delegatecall target",
			mutate: func(candidate *SafeTransaction, validation *SweepValidation) {
				candidate.Destination = ethcommon.HexToAddress("0x5555555555555555555555555555555555555555")
				sweepTestSeal(candidate, requestID)
				validation.TransactionHash = candidate.TxHash
			},
		},
		{
			name: "multisend selector",
			mutate: func(candidate *SafeTransaction, validation *SweepValidation) {
				candidate.Data[0] ^= 0xff
				sweepTestSeal(candidate, requestID)
				validation.TransactionHash = candidate.TxHash
			},
		},
		{
			name: "inner delegatecall",
			mutate: func(candidate *SafeTransaction, validation *SweepValidation) {
				candidate.Data[68] = operationTypeDelegateCall
				sweepTestSeal(candidate, requestID)
				validation.TransactionHash = candidate.TxHash
			},
		},
		{
			name: "truncated multisend",
			mutate: func(candidate *SafeTransaction, validation *SweepValidation) {
				candidate.Data = candidate.Data[:len(candidate.Data)-1]
				sweepTestSeal(candidate, requestID)
				validation.TransactionHash = candidate.TxHash
			},
		},
		{
			name: "balance mismatch",
			mutate: func(_ *SafeTransaction, validation *SweepValidation) {
				validation.Balances[token] = big.NewInt(201)
			},
		},
		{
			name: "destination mismatch",
			mutate: func(_ *SafeTransaction, validation *SweepValidation) {
				validation.AllowedDestination = "0x6666666666666666666666666666666666666666"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)
			candidate := sweepTestClone(tx)
			validation := sweepTestValidationClone(expected)
			test.mutate(candidate, &validation)
			_, err := ValidateSweepTransaction(candidate, validation)
			require.Error(err)
		})
	}
}

func TestExtractOutputsRejectsMalformedMultiSendWithoutPanicking(t *testing.T) {
	require := require.New(t)
	tx := &SafeTransaction{
		Destination: ethcommon.HexToAddress(EthereumMultiSendAddress),
		Value:       big.NewInt(0),
		Operation:   operationTypeDelegateCall,
	}
	malformed := [][]byte{
		nil,
		make([]byte, 4),
		append([]byte{0x8d, 0x80, 0xff, 0x0a}, make([]byte, 64)...),
	}
	for _, data := range malformed {
		tx.Data = data
		require.NotPanics(func() {
			outputs, err := tx.ExtractOutputs()
			require.Error(err)
			require.Empty(outputs)
		})
	}
}

func TestValidateDirectSweepTransactions(t *testing.T) {
	const (
		requestID = "0ca34767-3a70-4a28-afd9-51c9bce4ecf5"
		safe      = "0x1111111111111111111111111111111111111111"
		receiver  = "0x2222222222222222222222222222222222222222"
		token     = "0x3333333333333333333333333333333333333333"
		chainID   = int64(137)
	)
	tests := []struct {
		name   string
		typeID int
		token  string
		amount string
	}{
		{name: "native", typeID: TypeETHTx, token: EthereumEmptyAddress, amount: "100"},
		{name: "ERC20", typeID: TypeERC20Tx, token: token, amount: "200"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)
			nonce := big.NewInt(42)
			tx, err := CreateTransaction(t.Context(), test.typeID, chainID, requestID, safe, receiver, test.token, test.amount, nonce)
			require.NoError(err)
			amount, ok := new(big.Int).SetString(test.amount, 10)
			require.True(ok)
			outputs, err := ValidateSweepTransaction(tx, SweepValidation{
				SafeAddress:        safe,
				ChainID:            chainID,
				Nonce:              nonce,
				RequestID:          requestID,
				TransactionHash:    tx.TxHash,
				Balances:           map[string]*big.Int{test.token: amount},
				AllowedDestination: receiver,
			})
			require.NoError(err)
			require.Len(outputs, 1)
		})
	}
}

func sweepTestSeal(tx *SafeTransaction, requestID string) {
	tx.Message = tx.GetTransactionHash()
	tx.TxHash = sweepTestHash(requestID, tx.Message)
}

func sweepTestHash(requestID string, message []byte) string {
	return hex.EncodeToString(crypto.Keccak256(append([]byte(requestID), message...)))
}

func sweepTestClone(tx *SafeTransaction) *SafeTransaction {
	clone := *tx
	clone.Value = new(big.Int).Set(tx.Value)
	clone.SafeTxGas = new(big.Int).Set(tx.SafeTxGas)
	clone.BaseGas = new(big.Int).Set(tx.BaseGas)
	clone.GasPrice = new(big.Int).Set(tx.GasPrice)
	clone.Nonce = new(big.Int).Set(tx.Nonce)
	clone.Data = append([]byte(nil), tx.Data...)
	clone.Message = append([]byte(nil), tx.Message...)
	clone.Signatures = make([][]byte, len(tx.Signatures))
	for i, signature := range tx.Signatures {
		clone.Signatures[i] = append([]byte(nil), signature...)
	}
	return &clone
}

func sweepTestValidationClone(validation SweepValidation) SweepValidation {
	clone := validation
	clone.Nonce = new(big.Int).Set(validation.Nonce)
	clone.Balances = make(map[string]*big.Int, len(validation.Balances))
	for token, balance := range validation.Balances {
		clone.Balances[token] = new(big.Int).Set(balance)
	}
	return clone
}
