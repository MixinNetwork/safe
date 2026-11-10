package bitcoin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPCGetMempoolTransactionIDsNewestFirst(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request bitcoinRPCTestRequest
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		assert.Equal(t, "getrawmempool", request.Method)
		assert.JSONEq(t, "true", string(request.Params[0]))
		assert.NoError(t, json.NewEncoder(w).Encode(bitcoinRPCTestResponse{JSONRPC: "2.0", ID: request.ID,
			Result: map[string]any{"old": map[string]any{"time": 1}, "new-b": map[string]any{"time": 2}, "new-a": map[string]any{"time": 2}},
		}))
	}))
	t.Cleanup(server.Close)
	ids, err := RPCGetMempoolTransactionIDs(t.Context(), server.URL)
	require.NoError(t, err)
	require.Equal(t, []string{"new-a", "new-b", "old"}, ids)
}

func TestRPCGetTransactionOnceDoesNotRetry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	_, err := RPCGetTransactionOnce(t.Context(), ChainBitcoin, server.URL, "hash")
	require.Error(t, err)
	require.Equal(t, int32(1), calls.Load())
}

func TestRPCGetTransactionOnceDeadline(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(server.Close)
	defer close(release)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err := RPCGetTransactionOnce(ctx, ChainBitcoin, server.URL, "hash")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
