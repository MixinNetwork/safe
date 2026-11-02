package bitcoin

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBitcoinRPCRejectsMismatchedAndMissingResults(t *testing.T) {
	for _, result := range []any{nil, map[string]any{"hash": "other", "txid": "other"}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "result": result})
		}))
		t.Cleanup(server.Close)
		_, err := RPCGetBlock(server.URL, "expected")
		require.Error(t, err)
		_, err = RPCGetBlockWithTransactions(ChainBitcoin, server.URL, "expected")
		require.Error(t, err)
		_, err = RPCGetTransaction(ChainBitcoin, server.URL, "expected")
		require.Error(t, err)
	}
}

func TestBitcoinRPCRejectsHTTPFailureWithSuccessfulBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "result": "hash"})
	}))
	defer server.Close()
	_, err := callBitcoinRPC(server.URL, "getblockhash", []any{42})
	require.ErrorContains(t, err, "503")
}

func TestBitcoinRPCBlockHeightsPreserveIntegers(t *testing.T) {
	for _, test := range []struct {
		result string
		want   int64
		valid  bool
	}{
		{`{"blocks":0}`, 0, true},
		{`{"blocks":9007199254740993}`, 9007199254740993, true},
		{`{"blocks":9223372036854775807}`, math.MaxInt64, true},
		{`{"blocks":-1}`, 0, false},
		{`{"blocks":9223372036854775808}`, 0, false},
		{`{"blocks":null}`, 0, false},
		{`{}`, 0, false},
		{`null`, 0, false},
	} {
		t.Run(test.result, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"result":%s}`, test.result)
			}))
			defer server.Close()
			height, err := RPCGetBlockHeight(server.URL)
			if test.valid {
				require.NoError(t, err)
				require.Equal(t, test.want, height)
			} else {
				require.Error(t, err)
			}
		})
	}
}
