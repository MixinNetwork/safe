package ethereum

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type retryRPCTransport func(*http.Request) (*http.Response, error)

func (f retryRPCTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestEthereumRPCHTTPRetries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		body      string
		retryable bool
	}{
		{"request timeout", http.StatusRequestTimeout, "backend unavailable", true},
		{"rate limit", http.StatusTooManyRequests, "backend unavailable", true},
		{"server failure", http.StatusInternalServerError, "backend unavailable", true},
		{"gateway HTML", http.StatusBadGateway, "<html>Bad Gateway</html>", true},
		{"service unavailable", http.StatusServiceUnavailable, "backend unavailable", true},
		{"gateway timeout", http.StatusGatewayTimeout, "backend unavailable", true},
		{"gateway JSON error", http.StatusServiceUnavailable, `{"error":"backend unavailable"}`, true},
		{"bad request", http.StatusBadRequest, "invalid character in request", false},
		{"unauthorized", http.StatusUnauthorized, "session timeout", false},
		{"forbidden", http.StatusForbidden, "handshake forbidden", false},
		{"not found", http.StatusNotFound, "not found", false},
		{"unsupported method", http.StatusNotImplemented, "not implemented", false},
		{"RPC rejection", http.StatusInternalServerError, `{"result":null,"error":{"code":-5,"message":"transaction not found"}}`, false},
		{"already mined", http.StatusInternalServerError, `{"result":null,"error":{"code":-27,"message":"Transaction already in block chain"}}`, false},
		{"RPC timeout", http.StatusOK, `{"result":null,"error":{"code":-32000,"message":"execution timeout"}}`, true},
		{"RPC timeout over HTTP 500", http.StatusInternalServerError, `{"result":null,"error":{"code":-32000,"message":"execution timeout"}}`, true},
		{"RPC rate limit", http.StatusOK, `{"result":null,"error":{"code":-32005,"message":"Too Many Requests"}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = previous })
			calls := 0
			http.DefaultTransport = retryRPCTransport(func(r *http.Request) (*http.Response, error) {
				defer r.Body.Close()
				calls++
				status, body := tc.status, tc.body
				if calls > 1 {
					status, body = http.StatusOK, `{"result":"0x2a","error":null}`
				}
				return &http.Response{
					StatusCode: status,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(body)),
					Request:    r,
				}, nil
			})

			height, err := RPCGetBlockHeight("http://rpc.invalid")
			if tc.retryable {
				require.NoError(t, err)
				require.Equal(t, int64(42), height)
				require.Equal(t, 2, calls)
			} else {
				require.ErrorContains(t, err, tc.body)
				require.Zero(t, height)
				require.Equal(t, 1, calls, fmt.Sprintf("HTTP %d must not be retried", tc.status))
			}
		})
	}
}

func TestEthereumTraceRetriesExecutionTimeout(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	calls := 0
	http.DefaultTransport = retryRPCTransport(func(r *http.Request) (*http.Response, error) {
		defer r.Body.Close()
		calls++
		body := `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution timeout"}}`
		if calls > 1 {
			body = `{"jsonrpc":"2.0","id":1,"result":{"type":"CALL","value":"0x0"}}`
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	})

	trace, err := RPCDebugTraceTransactionByHash("http://rpc.invalid", "0x"+strings.Repeat("a", 64))
	require.NoError(t, err)
	require.NotNil(t, trace)
	require.Equal(t, "CALL", trace.Type)
	require.Equal(t, 2, calls)
}
