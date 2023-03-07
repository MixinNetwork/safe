package common

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
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

func DecodeHexOrPanic(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(s)
	}
	return b
}

func ShortSum(public string) []byte {
	sum := sha256.Sum256([]byte(public))
	return sum[:8]
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
