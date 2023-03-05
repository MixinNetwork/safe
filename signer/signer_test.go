package signer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/protocols/cmp"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/test-go/testify/assert"
)

func TestCMPSigner(t *testing.T) {
	assert := assert.New(t)
	ctx, nodes := TestPrepare(assert)

	public := testCMPKeyGen(ctx, assert, nodes, common.CurveSecp256k1ECDSABitcoin)
	testCMPSign(ctx, assert, nodes, public, []byte("mixin"), common.CurveSecp256k1ECDSABitcoin)
}

func TestSSID(t *testing.T) {
	assert := assert.New(t)

	_, nodes := TestPrepare(assert)
	node := nodes[0]
	sessionId := []byte("test-session-id")

	start, _ := cmp.Keygen(curve.Secp256k1{}, node.id, node.members, node.threshold, nil)(sessionId)
	assert.Equal("35a2625ae67f86f4f3f19ba3435aa98c3ead92afaa4b6833bb64bd47d3cc2aa0008ee5336c54fec31142a338ae53a60201d21d1b3990c8035e6dffceaa24ed99", hex.EncodeToString(start.SSID()))

	start, _ = frost.Keygen(curve.Secp256k1{}, node.id, node.members, node.threshold)(sessionId)
	assert.Equal("25d9a0d35e78928505dfea12864f1ca9a068896fc4a5990db2b35e31c50ab7f12b4ef2c8cc715fe688534deb592fbe38ce7aad7dc2625cf3f95496a739f16c1f", hex.EncodeToString(start.SSID()))

	start, _ = frost.KeygenTaproot(node.id, node.members, node.threshold)(sessionId)
	assert.Equal("b4ee4f1ad7294abdb0d09699e420c085c377580f0397c0daa0dae5b272c75e495bdb77146775ddd347050d0093459204189b75bbe5c5cc534817fce62d25df1d", hex.EncodeToString(start.SSID()))
}

func testCMPKeyGen(ctx context.Context, assert *assert.Assertions, nodes []*Node, crv byte) string {
	sid := mixin.UniqueConversationID("keygen", fmt.Sprint(400))
	for i := 0; i < 4; i++ {
		node := nodes[i]
		op := &common.Operation{
			Type:  common.OperationTypeKeygenInput,
			Id:    sid,
			Curve: crv,
		}
		memo := mtg.EncodeMixinExtra("", sid, string(node.encryptOperation(op)))
		out := &mtg.Output{
			AssetID:         node.conf.KeeperAssetId,
			Memo:            memo,
			TransactionHash: crypto.NewHash([]byte(op.Id)),
		}

		msg, _ := json.Marshal(out)
		network := node.network.(*testNetwork)
		network.mtgChannels[nodes[i].id] <- msg
	}

	var public string
	for _, node := range nodes {
		op := testWaitOperation(ctx, node, sid)
		assert.Equal(common.OperationTypeKeygenOutput, int(op.Type))
		assert.Equal(sid, op.Id)
		assert.Equal(crv, op.Curve)
		assert.Len(op.Public, 66)
		assert.Len(op.Extra, 1)
		assert.Equal(op.Extra[0], byte(common.RequestRoleSigner))
		public = op.Public
	}
	return public
}
