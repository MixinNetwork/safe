package signer

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/test-go/testify/require"
)

const (
	testMixinAddress = "XINZrJcfd6QoKrR7Q31YY7gk2zvbU1qkAAZ4xBan4KQYeDpTvAtMJQookpcjwbPDtJ4u8VELsbyymtLiUiEzpq6KtyjGNckr"
	testMixinViewKey = "19ba53a43576de8a61fcfce927a514db37a1f012e11bc5d6251b3d40c4ecb90b"

	CurveEdwards25519Mixin = 5
)

func TestFROSTMixinSign(t *testing.T) {
	require := require.New(t)
	ctx, nodes := TestPrepare(require)

	public := testFROSTPrepareKeys(ctx, require, nodes, CurveEdwards25519Mixin)

	addr := mixinAddress(public)
	require.Equal(testMixinAddress, addr.String())
	require.Equal(public, addr.PublicSpendKey.String())
	require.Equal(testMixinViewKey, addr.PrivateViewKey.String())
	require.Equal("5ad84042cf8b4eb9583506637317b6f6efc3d9675f7fb089591ed22f6fc5f0d2", addr.PublicViewKey.String())

	in0, _ := crypto.HashFromString("5b08c51b8e678e9015edd1561be644a787df257ebd7854b427c36d57989c3a43")
	in1, _ := crypto.HashFromString("b05c168ac64ee2c131245645d5ce36872a4229b77c4c998123550d3efd806b13")
	ver := common.NewTransactionV4(common.XINAssetId).AsVersioned()
	ver.AddInput(in0, 0)
	ver.AddInput(in1, 0)
	script := common.NewThresholdScript(1)
	amount := common.NewIntegerFromString("0.003")
	seed := crypto.NewHash([]byte("mixin safe"))
	ver.AddScriptOutput([]*common.Address{&addr}, script, amount, append(seed[:], seed[:]...))

	R0, _ := crypto.KeyFromString("d0f38355e2ee997de0344ebbfdf2110580dbd7e45bc6e136ab95b0ce163d603a")
	R1, _ := crypto.KeyFromString("4a3a42628e0bd26ce1e69dcaed4f495bece833a1f49af458051b1c169223bcc7")

	var sig0, sig1 crypto.Signature
	msg := ver.PayloadMarshal()

	msk := crypto.HashScalar(crypto.KeyMultPubPriv(&R0, &addr.PrivateViewKey), 0).Bytes()
	msk = writeStorageTransaction(ctx, nodes, append(msk, msg...))
	fsb := testFROSTSign(ctx, require, nodes, public, msk, CurveEdwards25519Mixin)
	require.Len(fsb, 64)
	copy(sig0[:], fsb)

	msk = crypto.HashScalar(crypto.KeyMultPubPriv(&R1, &addr.PrivateViewKey), 0).Bytes()
	msk = writeStorageTransaction(ctx, nodes, append(msk, msg...))
	fsb = testFROSTSign(ctx, require, nodes, public, msk, CurveEdwards25519Mixin)
	require.Len(fsb, 64)
	copy(sig1[:], fsb)

	ver.SignaturesMap = []map[uint16]*crypto.Signature{{
		0: &sig0,
	}, {
		0: &sig1,
	}}
	logger.Printf("%x\n", ver.Marshal())
}

func writeStorageTransaction(ctx context.Context, nodes []*Node, extra []byte) []byte {
	tx := crypto.Blake3Hash(extra)
	k := hex.EncodeToString(tx[:])
	v := hex.EncodeToString(extra)
	for _, n := range nodes {
		err := n.store.WriteProperty(ctx, k, v)
		if err != nil {
			panic(err)
		}
	}
	return tx[:]
}

func mixinAddress(public string) common.Address {
	var addr common.Address
	mpc, _ := hex.DecodeString(public)
	copy(addr.PublicSpendKey[:], mpc)
	addr.PrivateViewKey, _ = crypto.KeyFromString(testMixinViewKey)
	addr.PublicViewKey = addr.PrivateViewKey.Public()
	return addr
}
