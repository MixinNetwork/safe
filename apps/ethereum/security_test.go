package ethereum

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

const (
	securityTestRequestID = "0ca34767-3a70-4a28-afd9-51c9bce4ecf5"
	securityTestSafe      = "0x1111111111111111111111111111111111111111"
	securityTestReceiver  = "0x2222222222222222222222222222222222222222"
)

func TestSafeTransactionHashMatchesCanonicalV141(t *testing.T) {
	tx, err := CreateTransaction(
		t.Context(),
		TypeETHTx,
		1,
		securityTestRequestID,
		EthereumSafeL2Address,
		securityTestReceiver,
		EthereumEmptyAddress,
		"1000000000000000000",
		big.NewInt(42),
	)
	require.NoError(t, err)
	require.Equal(
		t,
		"37de7a396c3ce71c20c564db9a5b3f3019eb1481a8e6c86af0c00829982dbaf7",
		hex.EncodeToString(tx.Message),
	)
}

func TestSafeSignaturesBindCustodyFieldsAndRequest(t *testing.T) {
	keys := []*ecdsa.PrivateKey{
		securityTestEthereumPrivateKey(t, 1),
		securityTestEthereumPrivateKey(t, 2),
		securityTestEthereumPrivateKey(t, 3),
	}
	publics := make([]string, len(keys))
	for i, key := range keys {
		publics[i] = hex.EncodeToString(crypto.CompressPubkey(&key.PublicKey))
	}
	_, sortedPublics := GetSortedSafeOwners(publics[0], publics[1], publics[2])

	tx, err := CreateTransaction(
		t.Context(),
		TypeETHTx,
		1,
		securityTestRequestID,
		securityTestSafe,
		securityTestReceiver,
		EthereumEmptyAddress,
		"1000000000000000000",
		big.NewInt(42),
	)
	require.NoError(t, err)
	securityTestSignSafeTransaction(t, tx, sortedPublics, keys[0])
	securityTestSignSafeTransaction(t, tx, sortedPublics, keys[1])

	raw := hex.EncodeToString(tx.Marshal())
	require.True(t, CheckTransactionPartiallySignedBy(raw, publics[0]))
	require.True(t, CheckTransactionPartiallySignedBy(raw, publics[1]))

	expected := SweepValidation{
		SafeAddress:        securityTestSafe,
		ChainID:            1,
		Nonce:              big.NewInt(42),
		RequestID:          securityTestRequestID,
		TransactionHash:    tx.RequestHash,
		AllowedDestination: securityTestReceiver,
		Balances: map[string]*big.Int{
			EthereumEmptyAddress: big.NewInt(1_000_000_000_000_000_000),
		},
	}
	_, err = ValidateSweepTransaction(tx, expected)
	require.NoError(t, err)

	mutations := []struct {
		name  string
		apply func(*SafeTransaction)
	}{
		{name: "chain ID", apply: func(tx *SafeTransaction) { tx.ChainID++ }},
		{name: "Safe address", apply: func(tx *SafeTransaction) {
			tx.SafeAddress = "0x3333333333333333333333333333333333333333"
		}},
		{name: "destination", apply: func(tx *SafeTransaction) {
			tx.Destination = ethcommon.HexToAddress("0x4444444444444444444444444444444444444444")
		}},
		{name: "value", apply: func(tx *SafeTransaction) { tx.Value.Add(tx.Value, big.NewInt(1)) }},
		{name: "data", apply: func(tx *SafeTransaction) { tx.Data = []byte{1, 2, 3} }},
		{name: "operation", apply: func(tx *SafeTransaction) { tx.Operation = operationTypeDelegateCall }},
		{name: "safeTxGas", apply: func(tx *SafeTransaction) { tx.SafeTxGas.SetInt64(1) }},
		{name: "baseGas", apply: func(tx *SafeTransaction) { tx.BaseGas.SetInt64(1) }},
		{name: "gasPrice", apply: func(tx *SafeTransaction) { tx.GasPrice.SetInt64(1) }},
		{name: "gasToken", apply: func(tx *SafeTransaction) {
			tx.GasToken = ethcommon.HexToAddress("0x5555555555555555555555555555555555555555")
		}},
		{name: "refundReceiver", apply: func(tx *SafeTransaction) {
			tx.RefundReceiver = ethcommon.HexToAddress("0x6666666666666666666666666666666666666666")
		}},
		{name: "nonce", apply: func(tx *SafeTransaction) { tx.Nonce.Add(tx.Nonce, big.NewInt(1)) }},
	}

	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := sweepTestClone(tx)
			mutation.apply(candidate)
			mutatedHash := candidate.GetTransactionHash()
			require.False(t, bytes.Equal(tx.Message, mutatedHash))

			for i, signature := range candidate.Signatures {
				if signature == nil {
					continue
				}
				require.Error(t, VerifyMessageSignature(sortedPublics[i], mutatedHash, signature, true))
			}
			_, err := ValidateSweepTransaction(candidate, expected)
			require.Error(t, err)
		})
	}

	replayExpected := sweepTestValidationClone(expected)
	replayExpected.RequestID = "0ca34767-3a70-4a28-afd9-51c9bce4ecf6"
	_, err = ValidateSweepTransaction(sweepTestClone(tx), replayExpected)
	require.Error(t, err)
}

func TestERC20CustodySignaturesAndParserRejectSubstitution(t *testing.T) {
	const token = "0x3333333333333333333333333333333333333333"
	amount := big.NewInt(2_500_000)
	keys := []*ecdsa.PrivateKey{
		securityTestEthereumPrivateKey(t, 1),
		securityTestEthereumPrivateKey(t, 2),
		securityTestEthereumPrivateKey(t, 3),
	}
	publics := make([]string, len(keys))
	for i, key := range keys {
		publics[i] = hex.EncodeToString(crypto.CompressPubkey(&key.PublicKey))
	}
	_, sortedPublics := GetSortedSafeOwners(publics[0], publics[1], publics[2])

	tx, err := CreateTransaction(
		t.Context(),
		TypeERC20Tx,
		1,
		securityTestRequestID,
		securityTestSafe,
		securityTestReceiver,
		token,
		amount.String(),
		big.NewInt(42),
	)
	require.NoError(t, err)
	securityTestSignSafeTransaction(t, tx, sortedPublics, keys[0])
	securityTestSignSafeTransaction(t, tx, sortedPublics, keys[1])

	expected := SweepValidation{
		SafeAddress:        securityTestSafe,
		ChainID:            1,
		Nonce:              big.NewInt(42),
		RequestID:          securityTestRequestID,
		TransactionHash:    tx.RequestHash,
		AllowedDestination: securityTestReceiver,
		Balances: map[string]*big.Int{
			token: new(big.Int).Set(amount),
		},
	}
	outputs, err := ValidateSweepTransaction(tx, expected)
	require.NoError(t, err)
	require.Equal(t, []*Output{{
		TokenAddress: ethcommon.HexToAddress(token).Hex(),
		Destination:  ethcommon.HexToAddress(securityTestReceiver).Hex(),
		Amount:       amount,
	}}, outputs)

	mutations := []struct {
		name  string
		apply func(*SafeTransaction)
	}{
		{name: "token contract", apply: func(tx *SafeTransaction) {
			tx.Destination = ethcommon.HexToAddress("0x4444444444444444444444444444444444444444")
		}},
		{name: "embedded recipient", apply: func(tx *SafeTransaction) { tx.Data[35] ^= 0x01 }},
		{name: "raw token amount", apply: func(tx *SafeTransaction) { tx.Data[67] ^= 0x01 }},
	}
	for _, mutation := range mutations {
		t.Run("signed "+mutation.name, func(t *testing.T) {
			candidate := sweepTestClone(tx)
			mutation.apply(candidate)
			mutatedHash := candidate.GetTransactionHash()
			require.False(t, bytes.Equal(tx.Message, mutatedHash))
			for i, signature := range candidate.Signatures {
				if signature != nil {
					require.Error(t, VerifyMessageSignature(sortedPublics[i], mutatedHash, signature, true))
				}
			}
			_, err := ValidateSweepTransaction(candidate, expected)
			require.Error(t, err)
		})
	}

	parserMutations := []struct {
		name  string
		apply func(*SafeTransaction)
	}{
		{name: "approve selector", apply: func(tx *SafeTransaction) {
			copy(tx.Data[:4], ethcommon.FromHex("0x095ea7b3"))
		}},
		{name: "transferFrom selector and arguments", apply: func(tx *SafeTransaction) {
			copy(tx.Data[:4], ethcommon.FromHex("0x23b872dd"))
			tx.Data = append(tx.Data, make([]byte, 32)...)
		}},
		{name: "non-canonical recipient padding", apply: func(tx *SafeTransaction) { tx.Data[4] = 1 }},
		{name: "zero recipient", apply: func(tx *SafeTransaction) { clear(tx.Data[16:36]) }},
		{name: "zero amount", apply: func(tx *SafeTransaction) { clear(tx.Data[36:68]) }},
		{name: "trailing calldata", apply: func(tx *SafeTransaction) { tx.Data = append(tx.Data, 0) }},
		{name: "nonzero native value", apply: func(tx *SafeTransaction) { tx.Value.SetInt64(1) }},
		{name: "zero token contract", apply: func(tx *SafeTransaction) {
			tx.Destination = ethcommon.Address{}
		}},
	}
	for _, mutation := range parserMutations {
		t.Run("parser rejects "+mutation.name, func(t *testing.T) {
			candidate := sweepTestClone(tx)
			mutation.apply(candidate)
			outputs, err := candidate.ExtractOutputs()
			require.Error(t, err)
			require.Empty(t, outputs)
		})
	}
}

func securityTestEthereumPrivateKey(t *testing.T, scalar byte) *ecdsa.PrivateKey {
	t.Helper()
	encoded := make([]byte, 32)
	encoded[len(encoded)-1] = scalar
	key, err := crypto.ToECDSA(encoded)
	require.NoError(t, err)
	return key
}

func securityTestSignSafeTransaction(t *testing.T, tx *SafeTransaction, sortedPublics []string, key *ecdsa.PrivateKey) {
	t.Helper()
	public := hex.EncodeToString(crypto.CompressPubkey(&key.PublicKey))
	hash := HashMessageForSignature(hex.EncodeToString(tx.Message))
	signature, err := crypto.Sign(hash, key)
	require.NoError(t, err)
	signature = ProcessSignature(signature)
	require.NoError(t, VerifyMessageSignature(public, tx.Message, signature, true))

	for i, candidate := range sortedPublics {
		if candidate == public {
			tx.Signatures[i] = signature
			return
		}
	}
	t.Fatalf("Safe owner %s was not present", public)
}
