package ethereum

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEthereumBlocksRejectMismatchedIdentityAndOverflow(t *testing.T) {
	for _, test := range []struct {
		name   string
		result any
		call   func(string) error
	}{
		{"wrong hash", map[string]any{"hash": "other", "number": "0x2a", "timestamp": "0x1"}, func(rpc string) error { _, err := RPCGetBlock(t.Context(), rpc, "expected"); return err }},
		{"wrong height", map[string]any{"number": "0x2b", "timestamp": "0x1"}, func(rpc string) error { _, err := RPCGetBlockByHeight(t.Context(), rpc, 42); return err }},
		{"wrong full block height", map[string]any{"number": "0x2b", "transactions": []any{}}, func(rpc string) error { _, err := RPCGetBlockWithTransactions(t.Context(), rpc, 42); return err }},
		{"overflow height", "0x8000000000000000", func(rpc string) error { _, err := RPCGetBlockHeight(t.Context(), rpc); return err }},
		{"overflow timestamp", map[string]any{"hash": "expected", "number": "0x2a", "timestamp": "0x8000000000000000"}, func(rpc string) error { _, err := RPCGetBlock(t.Context(), rpc, "expected"); return err }},
		{"overflow height timestamp", map[string]any{"number": "0x2a", "timestamp": "0x8000000000000000"}, func(rpc string) error { _, err := RPCGetBlockByHeight(t.Context(), rpc, 42); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Error(t, test.call(regressionEthereumRPC(t, test.result)))
		})
	}
}

func TestEthereumRPCRejectsHTTPFailureWithSuccessfulBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "result": "0x2a"})
	}))
	defer server.Close()
	_, err := callEthereumRPC(t.Context(), server.URL, "eth_blockNumber", nil)
	require.ErrorContains(t, err, "503")
}
