package ethereum

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEthereumRPCRejectsMissingAndMalformedResults(t *testing.T) {
	const hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, tc := range []struct {
		name   string
		result any
		call   func(string) error
	}{
		{"missing block", nil, func(rpc string) error { _, err := RPCGetBlockByHeight(rpc, 42); return err }},
		{"missing transaction", nil, func(rpc string) error { _, err := RPCGetTransactionByHash(rpc, hash); return err }},
		{"different hash", map[string]any{"hash": "wrong"}, func(rpc string) error { _, err := RPCGetTransactionByHash(rpc, hash); return err }},
		{"invalid block number", map[string]any{"hash": hash, "blockNumber": "0xzz"}, func(rpc string) error { _, err := RPCGetTransactionByHash(rpc, hash); return err }},
		{"null block transaction", map[string]any{"number": "0x2a", "transactions": []any{nil}}, func(rpc string) error { _, err := RPCGetBlockWithTransactions(rpc, 42); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rpc := regressionEthereumRPC(t, tc.result)
			require.Error(t, tc.call(rpc))
		})
	}
	for _, invalid := range []string{"", "0", "0x", "0xzz", "0x-1"} {
		t.Run("balance "+invalid, func(t *testing.T) {
			rpc := regressionEthereumRPC(t, invalid)
			_, err := RPCGetAssetBalanceAtBlock(rpc, securityTestSafe, EthereumEmptyAddress, 42)
			require.Error(t, err)
		})
	}
}

func regressionEthereumRPC(t *testing.T, result any) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request ethereumRPCTestRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}))
	t.Cleanup(server.Close)
	return server.URL
}
