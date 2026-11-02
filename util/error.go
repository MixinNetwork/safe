package util

import (
	"errors"
	"slices"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/fox-one/mixin-sdk-go/v3"
)

func IsErrorCodes(err error, codes ...int) bool {
	if mixin.IsErrorCodes(err, codes...) {
		return true
	}

	if value, ok := errors.AsType[bot.Error](err); ok {
		return slices.Contains(codes, value.Code)
	}
	if pointer, ok := errors.AsType[*bot.Error](err); ok && pointer != nil {
		return slices.Contains(codes, pointer.Code)
	}
	return false
}
