package messenger

import (
	"fmt"
	"strings"
)

var (
	ErrorDone = newError("DONE")
)

func newError(msg string) error {
	return fmt.Errorf("messenger error: %s", msg)
}

func checkRetryableError(err error) bool {
	es := err.Error()
	switch {
	case strings.Contains(es, "Client.Timeout exceeded"):
	case strings.Contains(es, "Bad Gateway"):
	case strings.Contains(es, "Internal Server Error"):
	default:
		return false
	}
	return true
}
