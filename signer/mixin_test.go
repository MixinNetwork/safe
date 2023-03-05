package signer

import (
	"encoding/hex"
	"testing"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/test-go/testify/assert"
)

const (
	testMixinAddress = "XINZrJcfd6QoKrR7Q31YY7gk2zvbU1qkAAZ4xBan4KQYeDpTvAtMJQookpcjwbPDtJ4u8VELsbyymtLiUiEzpq6KtyjGNckr"
	testMixinViewKey = "19ba53a43576de8a61fcfce927a514db37a1f012e11bc5d6251b3d40c4ecb90b"
	testGhostMask    = "7fc515ae3f73599471c691e79cb6d3e756c2caddb25114b3d9669978bee9cc05"

	CurveEdwards25519Mixin = 12
)

func TestFROSTMixinSign(t *testing.T) {
	assert := assert.New(t)
	ctx, nodes := TestPrepare(assert)

	public := testFROSTPrepareKeys(ctx, assert, nodes, CurveEdwards25519Mixin)

	addr := mixinAddress(public)
	assert.Equal(testMixinAddress, addr.String())
	assert.Equal(public, addr.PublicSpendKey.String())
	assert.Equal(testMixinViewKey, addr.PrivateViewKey.String())
	assert.Equal("5ad84042cf8b4eb9583506637317b6f6efc3d9675f7fb089591ed22f6fc5f0d2", addr.PublicViewKey.String())

	r, _ := crypto.KeyFromString(testGhostMask)
	R := r.Public()
	assert.Equal(testGhostMask, r.String())
	assert.Equal("827e14ca58aec0759d3f31f0dc0725f766022fa89fa479dfbdf423d3a5bc4b64", R.String())
	P := crypto.DeriveGhostPublicKey(&r, &addr.PublicViewKey, &addr.PublicSpendKey, 0)
	assert.Equal("393589aded8653ec2986bedd289bb06f530f431da35b96bfc1c16c710d2663f0", P.String())

	msg := crypto.HashScalar(crypto.KeyMultPubPriv(&R, &addr.PrivateViewKey), 0).Bytes()
	fsb := testFROSTSign(ctx, assert, nodes, public, append(msg, []byte("mixin")...), CurveEdwards25519Mixin)
	assert.Len(fsb, 64)
	var sig crypto.Signature
	copy(sig[:], fsb)
	assert.True(P.Verify([]byte("mixin"), sig))
}

func mixinAddress(public string) common.Address {
	var addr common.Address
	mpc, _ := hex.DecodeString(public)
	copy(addr.PublicSpendKey[:], mpc)
	addr.PrivateViewKey, _ = crypto.KeyFromString(testMixinViewKey)
	addr.PublicViewKey = addr.PrivateViewKey.Public()
	return addr
}
