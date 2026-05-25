package util

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strings"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/fox-one/mixin-sdk-go/v2"
)

func CheckRetryableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	es := strings.ToLower(err.Error())
	switch {
	case strings.Contains(es, "timeout"):
	case strings.Contains(es, "timed out"):
	case strings.Contains(es, "handshake"):
	case strings.Contains(es, "context deadline exceeded"):
	case strings.Contains(es, "connection reset by peer"):
	case strings.Contains(es, "upstream connect error or disconnect/reset before headers"):
	case strings.Contains(es, "bad gateway"):
	case strings.Contains(es, "internal server error"):
	case strings.Contains(es, "invalid character '<' looking for beginning of value"):
	case strings.Contains(es, "unexpected end of json input"):
	default:
		return false
	}
	return true
}

func IsErrorCodes(err error, codes ...int) bool {
	if mixin.IsErrorCodes(err, codes...) {
		return true
	}

	e := &bot.Error{}
	if errors.As(err, e) {
		return slices.ContainsFunc(codes, func(c int) bool {
			return c == e.Code
		})
	}
	return false
}
