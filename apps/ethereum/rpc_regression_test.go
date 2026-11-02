package ethereum

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestEthereumRPCRejectsMalformedCallTraces(t *testing.T) {
	for _, tc := range []struct {
		name  string
		trace *RPCTransactionCallTrace
	}{
		{"missing trace", nil},
		{"missing child", &RPCTransactionCallTrace{Type: "CALL", Calls: []*RPCTransactionCallTrace{nil}}},
		{"short value", &RPCTransactionCallTrace{Type: "CALL", Value: "0"}},
		{"invalid value", &RPCTransactionCallTrace{Type: "CALL", Value: "0xzz"}},
		{"negative value", &RPCTransactionCallTrace{Type: "CALL", Value: "0x-1"}},
		{"overflow value", &RPCTransactionCallTrace{Type: "CALL", Value: "0x1" + strings.Repeat("0", 64)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RPCDebugTraceTransactionByHash(regressionEthereumRPC(t, tc.trace), "hash")
			require.Error(t, err)
			result := []*RPCBlockCallTrace{{Result: tc.trace}}
			_, err = RPCDebugTraceBlockByNumber(regressionEthereumRPC(t, result), 42)
			require.Error(t, err)
		})
	}
	for _, traces := range [][]*RPCBlockCallTrace{nil, {nil}} {
		_, err := RPCDebugTraceBlockByNumber(regressionEthereumRPC(t, traces), 42)
		require.Error(t, err)
	}

	trace := &RPCTransactionCallTrace{Type: "CALL", Value: "0x1", Calls: []*RPCTransactionCallTrace{
		{Type: "STATICCALL"}, {Type: "CALL", Value: "0x0", Error: "execution reverted"},
	}}
	actual, err := RPCDebugTraceTransactionByHash(regressionEthereumRPC(t, trace), "hash")
	require.NoError(t, err)
	require.Equal(t, trace, actual)
	block, err := RPCDebugTraceBlockByNumber(regressionEthereumRPC(t, []*RPCBlockCallTrace{{Result: trace}}), 42)
	require.NoError(t, err)
	require.Equal(t, trace, block[0].Result)
	empty, err := RPCDebugTraceBlockByNumber(regressionEthereumRPC(t, []*RPCBlockCallTrace{}), 42)
	require.NoError(t, err)
	require.Empty(t, empty)
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
