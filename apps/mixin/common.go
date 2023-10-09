package mixin

import (
	"bytes"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

const (
	ChainMixinKernel = 3
	ValuePrecision   = 8
	ValueDust        = 10000
)

func HashMessageForSignature(msg string) []byte {
	var buf bytes.Buffer
	prefix := "Mixin Signed Message:\n"
	_ = wire.WriteVarString(&buf, 0, prefix)
	_ = wire.WriteVarString(&buf, 0, msg)
	return chainhash.DoubleHashB(buf.Bytes())
}
