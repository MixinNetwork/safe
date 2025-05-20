package util

import (
	"crypto/md5"
	"strings"

	"github.com/gofrs/uuid/v5"
)

func UniqueId(a, b string) string {
	minID, maxID := a, b
	if strings.Compare(a, b) > 0 {
		maxID, minID = a, b
	}

	return uuidHash([]byte(minID + maxID))
}

func SplitIds(s, sep string) []string {
	if strings.TrimSpace(s) != s {
		panic(s)
	}
	if s == "" {
		return make([]string, 0)
	}
	a := strings.Split(s, sep)
	for _, e := range a {
		if strings.TrimSpace(e) == "" {
			panic(s)
		}
	}
	return a
}

func uuidHash(b []byte) string {
	h := md5.New()
	h.Write(b)
	sum := h.Sum(nil)
	sum[6] = (sum[6] & 0x0f) | 0x30
	sum[8] = (sum[8] & 0x3f) | 0x80
	return uuid.Must(uuid.FromBytes(sum)).String()
}
