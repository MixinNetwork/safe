package common

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"sort"

	"github.com/MixinNetwork/mixin/common"
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

type IndexedBytes struct {
	Index int
	Data  []byte
}

func EncodeIndexedBytesSorted(bm []*IndexedBytes) []byte {
	sort.Slice(bm, func(i, j int) bool { return bm[i].Index < bm[j].Index })
	enc := common.NewEncoder()
	enc.WriteInt(len(bm))
	for _, ib := range bm {
		enc.WriteInt(ib.Index)
		enc.WriteInt(len(ib.Data))
		enc.Write(ib.Data)
	}
	return enc.Bytes()
}

func DecodeIndexedBytesSorted(b []byte) []*IndexedBytes {
	dec := common.NewDecoder(b)
	num, err := dec.ReadInt()
	if err != nil {
		panic(err)
	}

	var bundle []*IndexedBytes
	for ; num > 0; num-- {
		index, err := dec.ReadInt()
		if err != nil {
			panic(err)
		}
		data, err := dec.ReadBytes()
		if err != nil {
			panic(err)
		}
		bundle = append(bundle, &IndexedBytes{index, data})
	}

	sort.Slice(bundle, func(i, j int) bool { return bundle[i].Index < bundle[j].Index })
	return bundle
}
