package util

import (
	"errors"
	"fmt"
	"io"
	"net/http"
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
		{"handshake", errors.New("TLS handshake failed"), true},
		{"malformed response", errors.New("invalid character '<' looking for beginning of value"), true},
		{"other error", errors.New("invalid URL"), false},
		{"gateway JSON error", &RPCResponseError{http.StatusServiceUnavailable, `{"error":"backend unavailable"}`}, true},
		{"authorization failure", &RPCResponseError{http.StatusUnauthorized, "session timeout"}, false},
		{"JSON-RPC rejection over HTTP 500", &RPCResponseError{http.StatusInternalServerError, `{"error":{"code":-5,"message":"invalid character in transaction"}}`}, false},
		{"JSON-RPC rejection over HTTP 200", &RPCResponseError{http.StatusOK, `{"error":{"code":-5,"message":"session timeout"}}`}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, CheckRetryableRPCError(test.err))
			if test.err != nil {
				require.Equal(t, test.want, CheckRetryableRPCError(fmt.Errorf("RPC request: %w", test.err)))
			}
		})
	}
	require.Contains(t, (&RPCResponseError{http.StatusServiceUnavailable, "backend unavailable"}).Error(), "HTTP 503 Service Unavailable (backend unavailable)")
}
