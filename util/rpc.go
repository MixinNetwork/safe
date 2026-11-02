package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// RPCResponseError preserves the HTTP status and body for retry decisions.
type RPCResponseError struct {
	StatusCode int
	Body       string
}

func (e *RPCResponseError) Error() string {
	return fmt.Sprintf("RPC error: HTTP %d %s (%s)", e.StatusCode, http.StatusText(e.StatusCode), e.Body)
}

// CheckRetryableRPCError distinguishes HTTP failures from JSON-RPC rejections
// before falling back to the transient transport and decoding errors.
func CheckRetryableRPCError(err error) bool {
	if err == nil {
		return false
	}
	if response, ok := errors.AsType[*RPCResponseError](err); ok {
		// Nodes can return a JSON-RPC rejection with HTTP 500. Such a response
		// must not be retried just because of its status or message text.
		var result struct {
			Error *struct {
				Code    *int    `json:"code"`
				Message *string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal([]byte(response.Body), &result) == nil &&
			result.Error != nil && result.Error.Code != nil && result.Error.Message != nil {
			return false
		}
		switch response.StatusCode {
		case http.StatusRequestTimeout, http.StatusTooManyRequests,
			http.StatusInternalServerError, http.StatusBadGateway,
			http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		default:
			return false
		}
	}

	reason := strings.ToLower(err.Error())
	return strings.Contains(reason, "timeout") ||
		strings.Contains(reason, "eof") ||
		strings.Contains(reason, "handshake") ||
		strings.Contains(reason, "invalid character")
}
