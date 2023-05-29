package common

import (
	"encoding/hex"
	"testing"

	"github.com/test-go/testify/assert"
)

func TestOperation(t *testing.T) {
	assert := assert.New(t)

	sid := "c94ac88f-4671-3976-b60a-09064f1811e8"
	public := "02a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc"
	msg, _ := hex.DecodeString("a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc")

	crv := NormalizeCurve(CurveSecp256k1ECDSABitcoinCash)
	assert.Equal(int(crv), CurveSecp256k1ECDSABitcoin)
	crv = NormalizeCurve(CurveSecp256k1ECDSABitcoin)
	assert.Equal(int(crv), CurveSecp256k1ECDSABitcoin)
	crv = NormalizeCurve(CurveSecp256k1ECDSALitecoin)
	assert.Equal(int(crv), CurveSecp256k1ECDSABitcoin)

	crv = NormalizeCurve(CurveSecp256k1ECDSAEthereum)
	assert.Equal(int(crv), CurveSecp256k1ECDSAEthereum)

	op := &Operation{
		Type:   OperationTypeSignInput,
		Id:     sid,
		Curve:  CurveSecp256k1ECDSABitcoin,
		Public: hex.EncodeToString(Fingerprint(public)),
		Extra:  msg,
	}

	assert.Equal("c94ac88f46713976b60a09064f1811e8020108fe6b4cb83c12753420a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc", hex.EncodeToString(op.Encode()))
	ob, _ := hex.DecodeString("c94ac88f46713976b60a09064f1811e8020108fe6b4cb83c12753420a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc")
	op, _ = DecodeOperation(ob)
	assert.Equal(OperationTypeSignInput, int(op.Type))
	assert.Equal(sid, op.Id)
	assert.Equal(CurveSecp256k1ECDSABitcoin, int(op.Curve))
	assert.Equal("fe6b4cb83c127534", op.Public)
	assert.Equal("a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc", hex.EncodeToString(op.Extra))

	op = &Operation{
		Type:  OperationTypeKeygenInput,
		Id:    sid,
		Curve: CurveSecp256k1ECDSABitcoin,
	}
	assert.Equal("c94ac88f46713976b60a09064f1811e801010000", hex.EncodeToString(op.Encode()))
	ob, _ = hex.DecodeString("c94ac88f46713976b60a09064f1811e801010000")
	op, _ = DecodeOperation(ob)
	assert.Equal(OperationTypeKeygenInput, int(op.Type))
	assert.Equal(sid, op.Id)
	assert.Equal(CurveSecp256k1ECDSABitcoin, int(op.Curve))
	assert.Equal("", op.Public)
	assert.Equal("", hex.EncodeToString(op.Extra))

	assert.Equal("feL`4xL1,UGP^(,bIw]q$AAAA", Base91Encode(op.Encode()))
}
