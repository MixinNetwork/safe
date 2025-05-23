package signer

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/mixin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

func TestFROSTSigner(t *testing.T) {
	require := require.New(t)
	ctx, nodes, saverStore := TestPrepare(require)

	msg := []byte("mixin safe")
	public := testFROSTKeyGen(ctx, require, nodes, common.CurveEdwards25519Default)
	testSaverItemsCheck(ctx, require, nodes, saverStore, 1)

	path := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	require.True(mixin.CheckEd25519ValidChildPath(path))
	sig := testFROSTSign(ctx, require, nodes, public, msg, path, common.CurveEdwards25519Default)
	child := mixin.DeriveEd25519Child(public, path)
	require.NotEqual(public, hex.EncodeToString(child))
	valid := ed25519.Verify(child, msg, sig)
	require.True(valid)
	testSaverItemsCheck(ctx, require, nodes, saverStore, 1)

	path = []byte{0, 0, 0, 0, 0, 0, 0, 0}
	require.False(mixin.CheckEd25519ValidChildPath(path))
	sig = testFROSTSign(ctx, require, nodes, public, msg, path, common.CurveEdwards25519Default)
	child, _ = hex.DecodeString(public)
	valid = ed25519.Verify(child, msg, sig)
	require.True(valid)
	testSaverItemsCheck(ctx, require, nodes, saverStore, 1)

	public = testFROSTKeyGen(ctx, require, nodes, common.CurveSecp256k1SchnorrBitcoin)
	testFROSTSign(ctx, require, nodes, public, msg, []byte{0, 0, 0, 0}, common.CurveSecp256k1SchnorrBitcoin)
	testSaverItemsCheck(ctx, require, nodes, saverStore, 2)
}

func testFROSTKeyGen(ctx context.Context, require *require.Assertions, nodes []*Node, curve uint8) string {
	sequence += 100
	sid := common.UniqueId("keygen", fmt.Sprint(curve))
	for i := range 4 {
		node := nodes[i]
		op := &common.Operation{
			Type:  common.OperationTypeKeygenInput,
			Id:    sid,
			Curve: curve,
		}
		memo := mtg.EncodeMixinExtraBase64(node.conf.AppId, node.encryptOperation(op))
		memo = hex.EncodeToString([]byte(memo))
		out := &mtg.Action{
			UnifiedOutput: mtg.UnifiedOutput{
				OutputId:           uuid.Must(uuid.NewV4()).String(),
				TransactionHash:    crypto.Sha256Hash([]byte(op.Id)).String(),
				AppId:              node.conf.AppId,
				AssetId:            node.conf.KeeperAssetId,
				Extra:              memo,
				Amount:             decimal.NewFromInt(1),
				Sequence:           sequence,
				SequencerCreatedAt: time.Now(),
			},
		}

		msg := common.MarshalJSONOrPanic(out)
		network := node.network.(*testNetwork)
		network.mtgChannel(nodes[i].id) <- msg
	}

	var public string
	for _, node := range nodes {
		op := testWaitOperation(ctx, node, sid)
		logger.Verbosef("testWaitOperation(%s, %s) => %v\n", node.id, sid, op)
		require.Equal(common.OperationTypeKeygenOutput, int(op.Type))
		require.Equal(sid, op.Id)
		require.Equal(curve, op.Curve)
		require.Len(op.Public, 64)
		require.Len(op.Extra, 34)
		require.Equal(op.Extra[0], byte(common.RequestRoleSigner))
		require.Equal(op.Extra[33], byte(common.RequestFlagNone))
		public = op.Public
	}
	return public
}

func testFROSTSign(ctx context.Context, require *require.Assertions, nodes []*Node, public string, msg, path []byte, crv uint8) []byte {
	sequence += 100
	node := nodes[0]
	sid := common.UniqueId("sign", fmt.Sprintf("%d:%x:%d", crv, msg, sequence))
	fp := common.Fingerprint(public)
	fingerPath := append(fp, path...)
	sop := &common.Operation{
		Type:   common.OperationTypeSignInput,
		Id:     sid,
		Curve:  crv,
		Public: hex.EncodeToString(fingerPath),
		Extra:  msg,
	}
	memo := mtg.EncodeMixinExtraBase64(node.conf.AppId, node.encryptOperation(sop))
	memo = hex.EncodeToString([]byte(memo))
	out := &mtg.Action{
		UnifiedOutput: mtg.UnifiedOutput{
			OutputId:           uuid.Must(uuid.NewV4()).String(),
			TransactionHash:    crypto.Sha256Hash([]byte(sop.Id)).String(),
			AppId:              node.conf.AppId,
			AssetId:            node.conf.KeeperAssetId,
			Extra:              memo,
			Amount:             decimal.NewFromInt(1),
			Sequence:           sequence,
			SequencerCreatedAt: time.Now(),
		},
	}
	op := TestProcessOutput(ctx, require, nodes, out, sid)
	require.True(node.store.CheckActionResultsBySessionId(ctx, sid))

	require.Equal(common.OperationTypeSignOutput, int(op.Type))
	require.Equal(sid, op.Id)
	require.Equal(crv, op.Curve)
	require.Len(op.Public, 64)
	require.Len(op.Extra, 64)

	_, _, share, err := node.store.ReadKeyByFingerprint(ctx, hex.EncodeToString(fp))
	require.Nil(err)
	require.NotNil(share)
	extra := node.concatMessageAndSignature(msg, op.Extra)
	res, _ := node.verifySessionSignature(ctx, crv, public, extra, share, path)
	require.True(res)

	return op.Extra
}
