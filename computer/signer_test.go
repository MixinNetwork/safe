package computer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/protocols/cmp"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/saver"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

func TestCMPSigner(t *testing.T) {
	require := require.New(t)
	ctx, nodes, saverStore := TestPrepare(require)
	public, chainCode := testCMPKeyGen(ctx, require, nodes, common.CurveSecp256k1ECDSABitcoin)
	testSaverItemsCheck(ctx, require, nodes, saverStore, 1)

	sig := testCMPSign(ctx, require, nodes, public, []byte("mixin"), common.CurveSecp256k1ECDSABitcoin)
	t.Logf("testCMPSign(%s) => %x\n", public, sig)
	err := bitcoin.VerifySignatureDER(public, []byte("mixin"), sig)
	require.Nil(err)

	path := []byte{1, 0, 0, 0}
	sig = testCMPSignWithPath(ctx, require, nodes, public, []byte("mixin"), common.CurveSecp256k1ECDSABitcoin, path)
	t.Logf("testCMPSignWithPath(%s, %v) => %x\n", public, path, sig)
	_, cp, err := bitcoin.DeriveBIP32(public, chainCode, 0)
	require.Nil(err)
	err = bitcoin.VerifySignatureDER(cp, []byte("mixin"), sig)
	require.Nil(err)

	path = []byte{1, 123, 0, 0}
	sig = testCMPSignWithPath(ctx, require, nodes, public, []byte("mixin"), common.CurveSecp256k1ECDSABitcoin, path)
	t.Logf("testCMPSignWithPath(%s, %v) => %x\n", public, path, sig)
	_, cp, err = bitcoin.DeriveBIP32(public, chainCode, 123)
	require.Nil(err)
	err = bitcoin.VerifySignatureDER(cp, []byte("mixin"), sig)
	require.Nil(err)

	path = []byte{2, 123, 220, 255}
	sig = testCMPSignWithPath(ctx, require, nodes, public, []byte("mixin"), common.CurveSecp256k1ECDSABitcoin, path)
	t.Logf("testCMPSignWithPath(%s, %v) => %x\n", public, path, sig)
	_, cp, err = bitcoin.DeriveBIP32(public, chainCode, 123, 220)
	require.Nil(err)
	err = bitcoin.VerifySignatureDER(cp, []byte("mixin"), sig)
	require.Nil(err)

	path = []byte{3, 123, 220, 255}
	sig = testCMPSignWithPath(ctx, require, nodes, public, []byte("mixin"), common.CurveSecp256k1ECDSABitcoin, path)
	t.Logf("testCMPSignWithPath(%s, %v) => %x\n", public, path, sig)
	_, cp, err = bitcoin.DeriveBIP32(public, chainCode, 123, 220, 255)
	require.Nil(err)
	err = bitcoin.VerifySignatureDER(cp, []byte("mixin"), sig)
	require.Nil(err)
}

func TestSSID(t *testing.T) {
	require := require.New(t)

	_, nodes, _ := TestPrepare(require)
	node := nodes[0]
	sessionId := []byte("test-session-id")

	start, _ := cmp.Keygen(curve.Secp256k1{}, node.id, node.GetPartySlice(), node.threshold, nil)(sessionId)
	require.Equal("35a2625ae67f86f4f3f19ba3435aa98c3ead92afaa4b6833bb64bd47d3cc2aa0008ee5336c54fec31142a338ae53a60201d21d1b3990c8035e6dffceaa24ed99", hex.EncodeToString(start.SSID()))

	start, _ = frost.Keygen(curve.Secp256k1{}, node.id, node.GetPartySlice(), node.threshold)(sessionId)
	require.Equal("25d9a0d35e78928505dfea12864f1ca9a068896fc4a5990db2b35e31c50ab7f12b4ef2c8cc715fe688534deb592fbe38ce7aad7dc2625cf3f95496a739f16c1f", hex.EncodeToString(start.SSID()))

	start, _ = frost.KeygenTaproot(node.id, node.GetPartySlice(), node.threshold)(sessionId)
	require.Equal("b4ee4f1ad7294abdb0d09699e420c085c377580f0397c0daa0dae5b272c75e495bdb77146775ddd347050d0093459204189b75bbe5c5cc534817fce62d25df1d", hex.EncodeToString(start.SSID()))
}

func testCMPKeyGen(ctx context.Context, require *require.Assertions, nodes []*Node, crv byte) (string, []byte) {
	sid := common.UniqueId("keygen", fmt.Sprint(400))
	sequence := 4600000
	for i := 0; i < 4; i++ {
		node := nodes[i]
		op := &common.Operation{
			Type:  common.OperationTypeKeygenInput,
			Id:    sid,
			Curve: crv,
		}
		memo := mtg.EncodeMixinExtraBase64(node.conf.AppId, node.encryptOperation(op))
		memo = hex.EncodeToString([]byte(memo))
		out := &mtg.Action{
			UnifiedOutput: mtg.UnifiedOutput{
				OutputId:           uuid.Must(uuid.NewV4()).String(),
				TransactionHash:    crypto.Sha256Hash([]byte(op.Id)).String(),
				AppId:              node.conf.AppId,
				AssetId:            node.conf.AssetId,
				Extra:              memo,
				Amount:             decimal.NewFromInt(1),
				SequencerCreatedAt: time.Now(),
				Sequence:           uint64(sequence + i),
			},
		}

		msg := common.MarshalJSONOrPanic(out)
		network := node.network.(*testNetwork)
		network.mtgChannel(nodes[i].id) <- msg
	}

	var public string
	var chainCode []byte
	for _, node := range nodes {
		op := testWaitOperation(ctx, node, sid)
		logger.Verbosef("testWaitOperation(%s, %s) => %v\n", node.id, sid, op)
		require.Equal(common.OperationTypeKeygenOutput, int(op.Type))
		require.Equal(sid, op.Id)
		require.Equal(crv, op.Curve)
		require.Len(op.Public, 66)
		require.Len(op.Extra, 34)
		require.Equal(op.Extra[0], byte(common.RequestRoleSigner))
		require.Equal(op.Extra[33], byte(common.RequestFlagNone))
		public = op.Public
		chainCode = op.Extra[1:33]

		keys, err := node.store.ListUnbackupedKeys(ctx, 1)
		require.Nil(err)
		require.Len(keys, 0)
	}
	return public, chainCode
}

func testSaverItemsCheck(ctx context.Context, require *require.Assertions, nodes []*Node, saverStore *saver.SQLite3Store, count int) {
	for _, node := range nodes {
		items, err := saverStore.ListItemsForNode(ctx, string(node.id))
		require.Nil(err)
		require.Len(items, count)

		for _, item := range items {
			var body struct {
				Id        string           `json:"id"`
				NodeId    string           `json:"node_id"`
				SessionId string           `json:"session_id"`
				Public    string           `json:"public"`
				Share     string           `json:"share"`
				Signature crypto.Signature `json:"signature"`
			}
			err = json.Unmarshal([]byte(item.Data), &body)
			require.Nil(err)
			msg := body.Id + body.NodeId + body.SessionId + body.Public + body.Share
			hash := crypto.Sha256Hash([]byte(msg))
			key, err := crypto.KeyFromString(node.conf.SaverKey)
			require.Nil(err)
			pub := key.Public()
			require.True((&pub).Verify(hash, body.Signature))

			id := uuid.FromStringOrNil(item.Id)
			secret := crypto.Sha256Hash([]byte(node.saverKey.String() + id.String()))
			secret = crypto.Sha256Hash(secret[:])

			rb, err := base64.RawURLEncoding.DecodeString(body.Public)
			require.Nil(err)
			rb = common.AESDecrypt(secret[:], rb)
			op, err := common.DecodeOperation(rb)
			require.Nil(err)

			rb, err = base64.RawURLEncoding.DecodeString(body.Share)
			require.Nil(err)
			rb = common.AESDecrypt(secret[:], rb)
			decodedShare := rb[16:]

			public, crv, share, err := node.store.ReadKeyByFingerprint(ctx, hex.EncodeToString(common.Fingerprint(op.Public)))
			require.Nil(err)
			require.Equal(op.Public, public)
			require.Equal(op.Curve, crv)
			require.True(bytes.Equal(decodedShare, share))
		}
	}
}
