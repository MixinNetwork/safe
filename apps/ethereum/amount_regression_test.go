package ethereum

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestSafeTransactionRejectsUint256Overflow(t *testing.T) {
	tx, err := CreateTransaction(t.Context(), TypeETHTx, 1, securityTestRequestID,
		securityTestSafe, securityTestReceiver, EthereumEmptyAddress, "1", big.NewInt(0))
	require.NoError(t, err)
	key := securityTestEthereumPrivateKey(t, 1)
	public := hex.EncodeToString(crypto.CompressPubkey(&key.PublicKey))
	securityTestSignSafeTransaction(t, tx, []string{public}, key)
	require.True(t, CheckTransactionPartiallySignedBy(hex.EncodeToString(tx.Marshal()), public))

	for _, field := range []string{"value", "nonce"} {
		t.Run(field, func(t *testing.T) {
			candidate := sweepTestClone(tx)
			overflow := new(big.Int).Lsh(big.NewInt(1), 256)
			if field == "value" {
				candidate.Value.Add(candidate.Value, overflow)
			} else {
				candidate.Nonce.Add(candidate.Nonce, overflow)
			}
			// ABI uint256 packing discards the high bits, so hashing alone
			// cannot detect this change to the serialized transaction.
			require.Equal(t, tx.Message, candidate.GetTransactionHash())
			raw := candidate.Marshal()
			require.False(t, CheckTransactionPartiallySignedBy(hex.EncodeToString(raw), public))
			_, err := UnmarshalSafeTransaction(raw)
			require.Error(t, err)
		})
	}
}

func TestSafeTransactionConstructorsValidateUint256AmountsAndNonces(t *testing.T) {
	overflow := new(big.Int).Lsh(big.NewInt(1), 256)
	maximum := new(big.Int).Sub(new(big.Int).Set(overflow), big.NewInt(1))
	for _, tc := range []struct {
		name   string
		amount *big.Int
		nonce  *big.Int
		valid  bool
	}{
		{"zero nonce", big.NewInt(1), big.NewInt(0), true},
		{"maximum", maximum, maximum, true},
		{"zero amount", big.NewInt(0), big.NewInt(0), false},
		{"negative amount", big.NewInt(-1), big.NewInt(0), false},
		{"amount overflow", overflow, big.NewInt(0), false},
		{"missing nonce", big.NewInt(1), nil, false},
		{"negative nonce", big.NewInt(1), big.NewInt(-1), false},
		{"nonce overflow", big.NewInt(1), overflow, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, typ := range []int{TypeETHTx, TypeERC20Tx, TypeMultiSendTx} {
				var tx *SafeTransaction
				var err error
				require.NotPanics(t, func() {
					if typ == TypeMultiSendTx {
						tx, err = CreateMultiSendTransaction(t.Context(), 1, securityTestRequestID,
							securityTestSafe, []*Output{{TokenAddress: EthereumEmptyAddress,
								Destination: securityTestReceiver, Amount: tc.amount}}, tc.nonce)
					} else {
						tx, err = CreateTransaction(t.Context(), typ, 1, securityTestRequestID,
							securityTestSafe, securityTestReceiver, securityTestSafe, tc.amount.String(), tc.nonce)
					}
				})
				if tc.valid {
					require.NoError(t, err)
					_, err = UnmarshalSafeTransaction(tx.Marshal())
					require.NoError(t, err)
				} else {
					require.Error(t, err, "transaction type %d", typ)
					require.Nil(t, tx)
				}
			}
		})
	}
}

func TestSafeTransactionConstructorsRejectMissingOutputs(t *testing.T) {
	for _, outputs := range [][]*Output{nil, {nil}, {{Destination: securityTestReceiver}}} {
		require.NotPanics(t, func() {
			_, err := CreateMultiSendTransaction(t.Context(), 1, securityTestRequestID,
				securityTestSafe, outputs, big.NewInt(0))
			require.Error(t, err)
			_, err = CreateTransactionFromOutputs(t.Context(), TypeETHTx, 1, securityTestRequestID,
				securityTestSafe, outputs, big.NewInt(0))
			require.Error(t, err)
		})
	}
}
