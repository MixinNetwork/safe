package messenger

import (
	"fmt"
)

var (
	// ErrorDone indicates that the receive stream has ended. Context
	// cancellation is reported separately through ctx.Err().
	ErrorDone = newError("DONE")
)

func newError(msg string) error {
	return fmt.Errorf("messenger error: %s", msg)
}
