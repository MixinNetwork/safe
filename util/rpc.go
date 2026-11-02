package util

import (
	"fmt"
	"net/http"
	"strings"
)

// RPCResponseError includes the HTTP status and body in the error message.
type RPCResponseError struct {
	StatusCode int
	Body       string
}

func (e *RPCResponseError) Error() string {
	return fmt.Sprintf("RPC error: HTTP %d %s (%s)", e.StatusCode, http.StatusText(e.StatusCode), e.Body)
}

// CheckRetryableRPCError matches transient failures in the error message.
func CheckRetryableRPCError(err error) bool {
	if err == nil {
		return false
	}
	reason := strings.ToLower(err.Error())
	// These failures remain terminal even when their messages mention a
	// timeout or the node returns them with HTTP 500.
	for _, permanent := range []string{
		"http 400 ", "http 401 ", "http 403 ", "http 404 ",
		"transaction not found", "no such mempool or blockchain transaction",
		"transaction already in block chain", "mandatory-script-verify-flag-failed",
		"method not found", "invalid request", "invalid params", "execution reverted",
	} {
		if strings.Contains(reason, permanent) {
			return false
		}
	}
	for _, transient := range []string{
		"timeout", "timed out", "context deadline exceeded", "eof", "handshake", "invalid character",
		"connection refused", "connection reset by peer", "connection abort",
		"network is down", "network is unreachable", "no route to host", "broken pipe",
		"failure in name resolution", "server misbehaving",
		"too many requests", "internal server error", "bad gateway", "service unavailable",
	} {
		if strings.Contains(reason, transient) {
			return true
		}
	}
	return false
}
