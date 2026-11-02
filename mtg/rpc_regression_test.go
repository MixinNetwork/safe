package mtg

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MixinNetwork/mixin/common"
	"github.com/stretchr/testify/require"
)

func TestKernelTransactionRejectsMalformedResults(t *testing.T) {
	expected := common.NewTransactionV5(common.XINAssetId).AsVersioned()
	raw := hex.EncodeToString(expected.Marshal())
	for _, tc := range []struct {
		name string
		data any
		hash string
	}{
		{"wrong result type", "transaction", expected.PayloadHash().String()},
		{"missing hex", map[string]any{}, expected.PayloadHash().String()},
		{"wrong hex type", map[string]any{"hex": 123}, expected.PayloadHash().String()},
		{"invalid hex", map[string]any{"hex": "not-hex"}, expected.PayloadHash().String()},
		{"invalid transaction", map[string]any{"hex": "00"}, expected.PayloadHash().String()},
		{"wrong snapshot type", map[string]any{"hex": raw, "snapshot": 123}, expected.PayloadHash().String()},
		{"different transaction", map[string]any{"hex": raw, "snapshot": "confirmed"}, strings.Repeat("a", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": tc.data})
			}))
			t.Cleanup(server.Close)
			require.NotPanics(t, func() {
				tx, snapshot, err := GetKernelTransaction(server.URL, tc.hash)
				require.Error(t, err)
				require.Nil(t, tx)
				require.Empty(t, snapshot)
			})
		})
	}
}

func TestKernelTransactionAllowsMissingAndUnconfirmedResults(t *testing.T) {
	expected := common.NewTransactionV5(common.XINAssetId).AsVersioned()
	for _, data := range []any{nil, map[string]any{"hex": hex.EncodeToString(expected.Marshal())}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		}))
		t.Cleanup(server.Close)
		tx, snapshot, err := GetKernelTransaction(server.URL, expected.PayloadHash().String())
		require.NoError(t, err)
		require.Empty(t, snapshot)
		if data == nil {
			require.Nil(t, tx)
		} else {
			require.Equal(t, expected.PayloadHash(), tx.PayloadHash())
		}
	}
}
