package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBitcoinPrivateKeyRejectsModuloReduction(t *testing.T) {
	for _, key := range []string{"", "01", strings.Repeat("00", 32), strings.Repeat("ff", 32), strings.Repeat("01", 33)} {
		_, err := parseBitcoinPrivateKey(key)
		require.Error(t, err)
	}
	_, err := parseBitcoinPrivateKey(strings.Repeat("01", 32))
	require.NoError(t, err)
}
