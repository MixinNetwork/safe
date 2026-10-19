package mtg

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/stretchr/testify/require"
)

func TestSpendPublicKeyReturnsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": 401, "description": "unauthorized"}})
	}))
	t.Cleanup(server.Close)
	client := mixin.GetRestyClient()
	oldURL := client.BaseURL
	client.SetBaseURL(server.URL)
	t.Cleanup(func() { client.SetBaseURL(oldURL) })
	group := &Group{mixin: mixin.NewFromAccessToken("test")}
	_, err := group.getSpendPublicKeyUntilSufficient(t.Context())
	require.ErrorContains(t, err, "unauthorized")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = group.getSpendPublicKeyUntilSufficient(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestKernelTransactionStopsOnPermanentError(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid transaction hash"})
	}))
	t.Cleanup(server.Close)
	group := &Group{kernelRPC: server.URL}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := group.readKernelTransactionUntilSufficientImpl(ctx, "invalid")
	require.ErrorContains(t, err, "invalid transaction hash")
	require.Equal(t, int32(1), calls.Load())
}
