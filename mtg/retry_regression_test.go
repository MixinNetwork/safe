package mtg

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/stretchr/testify/require"
)

func TestCheckRetryableError(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		retryable bool
	}{
		{"nil", nil, false},
		{"connection refused", syscall.ECONNREFUSED, true},
		{"connection reset", syscall.ECONNRESET, true},
		{"connection aborted", syscall.ECONNABORTED, true},
		{"network down", syscall.ENETDOWN, true},
		{"network unreachable", syscall.ENETUNREACH, true},
		{"host unreachable", syscall.EHOSTUNREACH, true},
		{"broken pipe", syscall.EPIPE, true},
		{"timeout", syscall.ETIMEDOUT, true},
		{"temporary DNS failure", &net.DNSError{Err: "Temporary failure in name resolution", IsTemporary: true}, true},
		{"lowercase DNS failure", errors.New("lookup kernel.invalid: temporary failure in name resolution"), true},
		{"DNS server failure", &net.DNSError{Err: "server misbehaving", IsTemporary: true}, true},
		{"DNS timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, true},
		{"permanent DNS failure", &net.DNSError{Err: "no such host", IsNotFound: true}, false},
		{"deadline exceeded", context.DeadlineExceeded, true},
		{"canceled", context.Canceled, false},
		{"permission denied", syscall.EACCES, false},
		{"invalid transaction", errors.New("invalid transaction hash"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.retryable, CheckRetryableError(tc.err))
			if tc.err != nil {
				wrapped := fmt.Errorf("kernel request failed: %w", &url.Error{
					Op: "Post", URL: "http://kernel.invalid", Err: tc.err,
				})
				require.Equal(t, tc.retryable, CheckRetryableError(wrapped))
				require.Equal(t, tc.retryable, CheckRetryableError(errors.New(wrapped.Error())))
			}
		})
	}
}

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

type retryRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f retryRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestKernelTransactionRetriesConnectionRefused(t *testing.T) {
	expected := common.NewTransactionV5(common.XINAssetId).AsVersioned()
	body, err := json.Marshal(map[string]any{"data": map[string]any{
		"hex": hex.EncodeToString(expected.Marshal()), "snapshot": "confirmed",
	}})
	require.NoError(t, err)

	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	var calls int
	http.DefaultTransport = retryRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		defer req.Body.Close()
		calls++
		if calls == 1 {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(body))),
			Header:     make(http.Header),
		}, nil
	})

	group := &Group{kernelRPC: "http://kernel.invalid"}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	actual, err := group.readKernelTransactionUntilSufficientImpl(ctx, expected.PayloadHash().String())
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.Equal(t, expected.PayloadHash(), actual.PayloadHash())
	require.Equal(t, 2, calls)
}

func TestKernelTransactionRetriesTransientHTTPStatus(t *testing.T) {
	expected := common.NewTransactionV5(common.XINAssetId).AsVersioned()
	for _, status := range []int{
		http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					http.Error(w, "backend unavailable", status)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
					"hex": hex.EncodeToString(expected.Marshal()), "snapshot": "confirmed",
				}})
			}))
			t.Cleanup(server.Close)
			group := &Group{kernelRPC: server.URL}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			actual, err := group.readKernelTransactionUntilSufficientImpl(ctx, expected.PayloadHash().String())
			require.NoError(t, err)
			require.NotNil(t, actual)
			require.Equal(t, expected.PayloadHash(), actual.PayloadHash())
			require.Equal(t, int32(2), calls.Load())
		})
	}
}

func TestKernelTransactionStopsOnPermanentHTTPError(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
			}))
			t.Cleanup(server.Close)
			group := &Group{kernelRPC: server.URL}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			_, err := group.readKernelTransactionUntilSufficientImpl(ctx, "invalid")
			require.ErrorContains(t, err, fmt.Sprintf("%d %s", status, http.StatusText(status)))
			require.Equal(t, int32(1), calls.Load())
		})
	}
}
