package computer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/protocols/cmp"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/saver"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

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
