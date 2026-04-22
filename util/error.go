package util

import (
	"errors"
	"slices"
	"strings"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/fox-one/mixin-sdk-go/v2"
)

func CheckRetryableError(err error) bool {
	if err == nil {
		return false
	}
	es := strings.ToLower(err.Error())
	switch {
	case strings.Contains(es, "eof"):
	case strings.Contains(es, "timeout"):
	case strings.Contains(es, "timed out"):
	case strings.Contains(es, "handshake"):
	case strings.Contains(es, "context deadline exceeded"):
	case strings.Contains(es, "connection reset by peer"):
	case strings.Contains(es, "bad gateway"):
	case strings.Contains(es, "internal server error"):
	case strings.Contains(es, "invalid character"):
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
	if errors.As(err, e) && slices.Contains(codes, e.Code) {
		return true
	}
	return false
}
