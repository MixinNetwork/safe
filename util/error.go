package util

import (
	"errors"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/fox-one/mixin-sdk-go/v2"
)

func IsErrorCodes(err error, codes ...int) bool {
	if mixin.IsErrorCodes(err, codes...) {
		return true
	}

	e := &bot.Error{}
	if errors.As(err, e) {
		for _, code := range codes {
			if e.Code == code {
				return true
			}
		}
	}
	return false
}
