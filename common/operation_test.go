package common

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/safe/util"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/stretchr/testify/require"
)

func TestOperation(t *testing.T) {
	require := require.New(t)

	sid := "c94ac88f-4671-3976-b60a-09064f1811e8"
	public := "02a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc"
	msg, _ := hex.DecodeString("a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc")

	crv := NormalizeCurve(CurveSecp256k1ECDSABitcoinCash)
	require.Equal(int(crv), CurveSecp256k1ECDSABitcoin)
	crv = NormalizeCurve(CurveSecp256k1ECDSABitcoin)
	require.Equal(int(crv), CurveSecp256k1ECDSABitcoin)
	crv = NormalizeCurve(CurveSecp256k1ECDSALitecoin)
	require.Equal(int(crv), CurveSecp256k1ECDSABitcoin)

	crv = NormalizeCurve(CurveSecp256k1ECDSAEthereum)
	require.Equal(int(crv), CurveSecp256k1ECDSAEthereum)

	op := &Operation{
		Type:   OperationTypeSignInput,
		Id:     sid,
		Curve:  CurveSecp256k1ECDSABitcoin,
		Public: hex.EncodeToString(Fingerprint(public)),
		Extra:  msg,
	}

	require.Equal("c94ac88f46713976b60a09064f1811e8020108fe6b4cb83c12753420a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc", hex.EncodeToString(op.Encode()))
	ob, _ := hex.DecodeString("c94ac88f46713976b60a09064f1811e8020108fe6b4cb83c12753420a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc")
	op, _ = DecodeOperation(ob)
	require.Equal(OperationTypeSignInput, int(op.Type))
	require.Equal(sid, op.Id)
	require.Equal(CurveSecp256k1ECDSABitcoin, int(op.Curve))
	require.Equal("fe6b4cb83c127534", op.Public)
	require.Equal("a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc", hex.EncodeToString(op.Extra))

	op = &Operation{
		Type:  OperationTypeKeygenInput,
		Id:    sid,
		Curve: CurveSecp256k1ECDSABitcoin,
	}
	require.Equal("c94ac88f46713976b60a09064f1811e801010000", hex.EncodeToString(op.Encode()))
	ob, _ = hex.DecodeString("c94ac88f46713976b60a09064f1811e801010000")
	op, _ = DecodeOperation(ob)
	require.Equal(OperationTypeKeygenInput, int(op.Type))
	require.Equal(sid, op.Id)
	require.Equal(CurveSecp256k1ECDSABitcoin, int(op.Curve))
	require.Equal("", op.Public)
	require.Equal("", hex.EncodeToString(op.Extra))

	require.Equal("feL`4xL1,UGP^(,bIw]q$AAAA", Base91Encode(op.Encode()))
}

func Test404(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	asset, err := SafeReadAssetUntilSufficient(ctx, "c94ac88f-4671-3976-b60a-09064f1811e8")
	require.Nil(err)
	require.NotNil(asset)

	asset, err = bot.ReadAsset(ctx, "c94ac88f-4671-3976-b60a-09064f1811e9")
	require.Nil(asset)
	require.NotNil(err)
	require.True(util.IsErrorCodes(err, 404))

	a, err := mixin.ReadNetworkAsset(ctx, "c94ac88f-4671-3976-b60a-09064f1811e9")
	require.Nil(a)
	require.NotNil(err)
	require.True(util.IsErrorCodes(err, 404))
}
