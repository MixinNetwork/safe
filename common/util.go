package common

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"github.com/MixinNetwork/safe/util"
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
	return util.UniqueId(a, b)
}

func EnableTestEnvironment(ctx context.Context) context.Context {
	return util.EnableTestEnvironment(ctx)
}

func CheckTestEnvironment(ctx context.Context) bool {
	return util.CheckTestEnvironment(ctx)
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

func CheckTransactionRetryError(err string) bool {
	switch {
	case strings.Contains(err, "spent by other transaction"):
		return true
	case strings.Contains(err, "inputs locked by another transaction"):
		return true
	}
	return false
}

func Rollback(txn *sql.Tx) {
	err := txn.Rollback()
	const already = "transaction has already been committed or rolled back"
	if err != nil && !strings.Contains(err.Error(), already) {
		panic(err)
	}
}
