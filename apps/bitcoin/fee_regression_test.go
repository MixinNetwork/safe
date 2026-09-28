package bitcoin

import (
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMempoolAverageFeeHandlesNoUsableTransactions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mempool map[string]any
		want    int64
	}{
		{"empty", map[string]any{}, 0},
		{"zero virtual size", map[string]any{"zero": map[string]any{"fees": map[string]any{"base": 1}, "vsize": 0}}, 0},
		{"nonempty", map[string]any{"tx": map[string]any{"fees": map[string]any{"base": 0.00001}, "vsize": 100}}, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request bitcoinRPCTestRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if request.Method != "getrawmempool" {
					t.Errorf("unexpected method %s", request.Method)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(bitcoinRPCTestResponse{JSONRPC: "2.0", ID: request.ID, Result: tc.mempool})
			}))
			t.Cleanup(server.Close)
			fee, err := RPCGetMempoolAverageFeePerBytes(server.URL)
			require.NoError(t, err)
			require.Equal(t, big.NewInt(tc.want), fee)
		})
	}
}
