package util

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckRetryableRPCError(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{"no error", nil, false},
		{"end of response", io.EOF, true},
		{"timeout", errors.New("i/o timeout"), true},
		{"execution timeout", errors.New("execution timeout"), true},
		{"connection timeout", syscall.ETIMEDOUT, true},
		{"connection refused", syscall.ECONNREFUSED, true},
		{"connection reset", syscall.ECONNRESET, true},
		{"connection aborted", syscall.ECONNABORTED, true},
		{"network down", syscall.ENETDOWN, true},
		{"network unreachable", syscall.ENETUNREACH, true},
		{"host unreachable", syscall.EHOSTUNREACH, true},
		{"broken pipe", syscall.EPIPE, true},
		{"temporary DNS failure", errors.New("Temporary failure in name resolution"), true},
		{"DNS server failure", errors.New("lookup rpc.invalid: server misbehaving"), true},
		{"permanent DNS failure", errors.New("lookup rpc.invalid: no such host"), false},
		{"deadline exceeded", context.DeadlineExceeded, true},
		{"canceled", context.Canceled, false},
		{"handshake", errors.New("TLS handshake failed"), true},
		{"malformed response", errors.New("invalid character '<' looking for beginning of value"), true},
		{"other error", errors.New("invalid URL"), false},
		{"gateway JSON error", &RPCResponseError{http.StatusServiceUnavailable, `{"error":"backend unavailable"}`}, true},
		{"authorization failure", &RPCResponseError{http.StatusUnauthorized, "session timeout"}, false},
		{"missing transaction over HTTP 500", &RPCResponseError{http.StatusInternalServerError, `{"error":{"code":-5,"message":"No such mempool or blockchain transaction"}}`}, false},
		{"rejected transaction over HTTP 500", &RPCResponseError{http.StatusInternalServerError, `{"error":{"code":-26,"message":"mandatory-script-verify-flag-failed"}}`}, false},
		{"invalid params over HTTP 500", &RPCResponseError{http.StatusInternalServerError, `{"error":{"code":-32602,"message":"Invalid params"}}`}, false},
		{"execution reverted over HTTP 500", &RPCResponseError{http.StatusInternalServerError, `{"error":{"code":3,"message":"execution reverted"}}`}, false},
		{"JSON-RPC timeout over HTTP 200", &RPCResponseError{http.StatusOK, `{"error":{"code":-32000,"message":"execution timeout"}}`}, true},
		{"JSON-RPC timeout over HTTP 500", &RPCResponseError{http.StatusInternalServerError, `{"error":{"code":-32000,"message":"execution timeout"}}`}, true},
		{"JSON-RPC rate limit", &RPCResponseError{http.StatusOK, `{"error":{"code":-32005,"message":"Too Many Requests"}}`}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, CheckRetryableRPCError(test.err))
			if test.err != nil {
				require.Equal(t, test.want, CheckRetryableRPCError(fmt.Errorf("RPC request: %w", test.err)))
				require.Equal(t, test.want, CheckRetryableRPCError(errors.New(test.err.Error())))
			}
		})
	}
	require.Contains(t, (&RPCResponseError{http.StatusServiceUnavailable, "backend unavailable"}).Error(), "HTTP 503 Service Unavailable (backend unavailable)")
}
