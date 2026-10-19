package keeper

import (
	"math/big"
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

func TestTransactionAmountsRejectRoundingAndOverflow(t *testing.T) {
	for _, tc := range []struct {
		amount    string
		precision int32
		bits      int
		want      string
	}{
		{"0.00000001", 8, 63, "1"},
		{"1.230000000", 8, 63, "123000000"},
		{"92233720368.54775807", 8, 63, "9223372036854775807"},
		{"92233720368.54775808", 8, 63, ""},
		{"0.000100001", 8, 63, ""},
		{"1.00000001", 6, 256, ""},
		{"1.000001", 6, 256, "1000001"},
		{"1.000000000000000001", 18, 256, "1000000000000000001"},
		{"0", 8, 63, ""},
		{"-1", 8, 63, ""},
		{"1e2147483647", 8, 63, ""},
		{"1e-2147483648", 8, 63, ""},
	} {
		t.Run(tc.amount, func(t *testing.T) {
			value, err := parseTransactionAmount(decimal.RequireFromString(tc.amount), tc.precision, tc.bits)
			if tc.want == "" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, value.String())
		})
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 256)
	_, err := parseTransactionAmount(decimal.NewFromBigInt(limit, -18), 18, 256)
	require.Error(t, err)
	limit.Sub(limit, big.NewInt(1))
	value, err := parseTransactionAmount(decimal.NewFromBigInt(limit, -18), 18, 256)
	require.NoError(t, err)
	require.Equal(t, limit, value)
}
