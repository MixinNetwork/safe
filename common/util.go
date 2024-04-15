package common

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"github.com/fox-one/mixin-sdk-go/v2"
)

const (
	contextKeyEnvironment = "environment"
)

func MarshalPanic(m encoding.BinaryMarshaler) []byte {
	b, err := m.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func MarshalJSONOrPanic(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func DecodeHexOrPanic(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(s)
	}
	return b
}

func Fingerprint(public string) []byte {
	sum := sha256.Sum256([]byte(public))
	return sum[:8]
}

func UniqueId(a, b string) string {
	return mixin.UniqueConversationID(a, b)
}

func EnableTestEnvironment(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyEnvironment, "test")
}

func CheckTestEnvironment(ctx context.Context) bool {
	val := ctx.Value(contextKeyEnvironment)
	if val == nil {
		return false
	}
	env, ok := val.(string)
	return ok && env == "test"
}

func CheckUnique(args ...any) bool {
	filter := make(map[any]struct{})
	for _, k := range args {
		filter[k] = struct{}{}
	}
	return len(filter) == len(args)
}

func ExpandTilde(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	path = strings.Replace(path, "~", home, 1)
	return path
}

func CheckRetryableError(err error) bool {
	es := err.Error()
	switch {
	case strings.Contains(es, "Client.Timeout"):
	case strings.Contains(es, "Bad Gateway"):
	case strings.Contains(es, "Internal Server Error"):
	default:
		return false
	}
	return true
}
