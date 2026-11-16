package util

import (
	"context"
	"time"
)

func WaitOrDone(ctx context.Context, duration time.Duration) bool {
	select {
	case <-time.After(duration):
		return false
	case <-ctx.Done():
		return true
	}
}
