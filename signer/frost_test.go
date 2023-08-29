package signer

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

func TestFROSTSigner(t *testing.T) {
	require := require.New(t)
	ctx, nodes := TestPrepare(require)

	public := testFROSTKeyGen(ctx, require, nodes, common.CurveEdwards25519Default)
	testFROSTSign(ctx, require, nodes, public, []byte("mixin"), common.CurveEdwards25519Default)

	public = testFROSTKeyGen(ctx, require, nodes, common.CurveSecp256k1SchnorrBitcoin)
	testFROSTSign(ctx, require, nodes, public, []byte("mixin"), common.CurveSecp256k1SchnorrBitcoin)
}

func testFROSTKeyGen(ctx context.Context, require *require.Assertions, nodes []*Node, curve uint8) string {
	sid := mixin.UniqueConversationID("keygen", fmt.Sprint(curve))
	for i := 0; i < 4; i++ {
		node := nodes[i]
		op := &common.Operation{
			Type:  common.OperationTypeKeygenInput,
			Id:    sid,
			Curve: curve,
		}
		memo := mtg.EncodeMixinExtra("", sid, string(node.encryptOperation(op)))
		out := &mtg.Output{
			AssetID:         node.conf.KeeperAssetId,
			Memo:            memo,
			Amount:          decimal.NewFromInt(1),
			TransactionHash: crypto.NewHash([]byte(op.Id)),
			CreatedAt:       time.Now(),
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
		require.Len(op.Extra, 2)
		require.Equal(op.Extra[0], byte(common.RequestRoleSigner))
		require.Equal(op.Extra[1], byte(common.RequestFlagNone))
		public = op.Public
	}
	return public
}

func testFROSTSign(ctx context.Context, require *require.Assertions, nodes []*Node, public string, msg []byte, curve uint8) []byte {
	sid := mixin.UniqueConversationID("sign", fmt.Sprintf("%d:%x", curve, msg))
	fingerPath := append(common.Fingerprint(public), []byte{0, 0, 0, 0}...)
	network := nodes[0].network.(*testNetwork)
	for i := 0; i < 4; i++ {
		node := nodes[i]
		sop := &common.Operation{
			Type:   common.OperationTypeSignInput,
			Id:     sid,
			Curve:  curve,
			Public: hex.EncodeToString(fingerPath),
			Extra:  msg,
		}
		memo := mtg.EncodeMixinExtra("", sid, string(node.encryptOperation(sop)))
		out := &mtg.Output{
			AssetID:         node.conf.KeeperAssetId,
			Memo:            memo,
			Amount:          decimal.NewFromInt(1),
			TransactionHash: crypto.NewHash([]byte(sop.Id)),
			CreatedAt:       time.Now(),
		}

		msg := common.MarshalJSONOrPanic(out)
		network.mtgChannel(nodes[i].id) <- msg
	}

	var extra []byte
	for _, node := range nodes {
		op := testWaitOperation(ctx, node, sid)
		logger.Verbosef("testWaitOperation(%s, %s) => %v\n", node.id, sid, op)
		require.Equal(common.OperationTypeSignOutput, int(op.Type))
		require.Equal(sid, op.Id)
		require.Equal(curve, op.Curve)
		require.Len(op.Public, 64)
		require.Len(op.Extra, 64)
		extra = op.Extra
	}
	return extra
}

func testFROSTPrepareKeys(ctx context.Context, require *require.Assertions, nodes []*Node, curve uint8) string {
	const public = "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b"
	sid := mixin.UniqueConversationID("prepare", public)
	for _, node := range nodes {
		parts := strings.Split(testFROSTKeys[node.id], ";")
		pub, share := parts[0], parts[1]
		conf, _ := hex.DecodeString(share)
		require.Equal(public, pub)

		op := &common.Operation{Id: sid, Curve: curve, Type: common.OperationTypeKeygenInput}
		err := node.store.WriteSessionIfNotExist(ctx, op, crypto.NewHash([]byte(sid)), 0, time.Now(), false)
		require.Nil(err)
		err = node.store.WriteKeyIfNotExists(ctx, op.Id, curve, pub, conf)
		require.Nil(err)
	}
	return public
}

var testFROSTKeys = map[party.ID]string{
	"member-id-0": "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b;0001000b6d656d6265722d69642d3000020020fe4584dcd16c51736b64e329ef2fd51b4f1d98ee833cdc96ace16398fd243f080020fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b000000b9a46b6d656d6265722d69642d305820cd5b764c011927f356938f5ebdd5f825c6f07e72f07a67ab7da1b8ec291de8d56b6d656d6265722d69642d315820d059874222f3d7a00a98da49fe388141717541f7d6ba7b0baf01af63c03510796b6d656d6265722d69642d325820e8b3ba906961e5e2ab66405d7105c2b2c19695a34ae77e229dabc2ef59ec71386b6d656d6265722d69642d33582090115b147e3977a8d44f58d40cdece998bd4b204b02ad91da9756cfff9969298",
	"member-id-1": "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b;0001000b6d656d6265722d69642d3100020020c6ec44a22c007a43d7518ac10669424693b159534fa32dbe872a5169c8f7210c0020fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b000000b9a46b6d656d6265722d69642d305820cd5b764c011927f356938f5ebdd5f825c6f07e72f07a67ab7da1b8ec291de8d56b6d656d6265722d69642d315820d059874222f3d7a00a98da49fe388141717541f7d6ba7b0baf01af63c03510796b6d656d6265722d69642d325820e8b3ba906961e5e2ab66405d7105c2b2c19695a34ae77e229dabc2ef59ec71386b6d656d6265722d69642d33582090115b147e3977a8d44f58d40cdece998bd4b204b02ad91da9756cfff9969298",
	"member-id-2": "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b;0001000b6d656d6265722d69642d3200020020e6543b705f73a02061f97cdcc45a47934dc5ee9f7a9f382d417eb74128ea100f0020fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b000000b9a46b6d656d6265722d69642d305820cd5b764c011927f356938f5ebdd5f825c6f07e72f07a67ab7da1b8ec291de8d56b6d656d6265722d69642d315820d059874222f3d7a00a98da49fe388141717541f7d6ba7b0baf01af63c03510796b6d656d6265722d69642d325820e8b3ba906961e5e2ab66405d7105c2b2c19695a34ae77e229dabc2ef59ec71386b6d656d6265722d69642d33582090115b147e3977a8d44f58d40cdece998bd4b204b02ad91da9756cfff9969298",
	"member-id-3": "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b;0001000b6d656d6265722d69642d330002002071aa71e94f63b2b232bec3d74a0b05ee7d5857d40531fde3d8dc96211dfc0b010020fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b000000b9a46b6d656d6265722d69642d305820cd5b764c011927f356938f5ebdd5f825c6f07e72f07a67ab7da1b8ec291de8d56b6d656d6265722d69642d315820d059874222f3d7a00a98da49fe388141717541f7d6ba7b0baf01af63c03510796b6d656d6265722d69642d325820e8b3ba906961e5e2ab66405d7105c2b2c19695a34ae77e229dabc2ef59ec71386b6d656d6265722d69642d33582090115b147e3977a8d44f58d40cdece998bd4b204b02ad91da9756cfff9969298",
}
