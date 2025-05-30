package computer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/messenger"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

type partyContextTyp string

const partyContextKey = partyContextTyp("party")

var outputReferences = make(map[string][]crypto.Hash)

func writeOutputReferences(outputId string, references []crypto.Hash) {
	outputReferences[outputId] = references
}

func readOutputReferences(outputId string) []crypto.Hash {
	return outputReferences[outputId]
}

func TestProcessOutput(ctx context.Context, require *require.Assertions, nodes []*Node, out *mtg.Action, sessionId string) *common.Operation {
	out.TestAttachActionToGroup(nodes[0].group)
	network := nodes[0].network.(*testNetwork)
	for i := range 4 {
		data := common.MarshalJSONOrPanic(out)
		network.mtgChannel(nodes[i].id) <- data
	}

	var op *common.Operation
	for _, node := range nodes {
		op = testWaitOperation(ctx, node, sessionId)
		logger.Verbosef("testWaitOperation(%s, %s) => %v\n", node.id, sessionId, op)
	}
	return op
}

func testWaitOperation(ctx context.Context, node *Node, sessionId string) *common.Operation {
	timeout := time.Now().Add(time.Minute * 4)
	for ; time.Now().Before(timeout); time.Sleep(3 * time.Second) {
		val, err := node.store.ReadProperty(ctx, "SIGNER:"+sessionId)
		if err != nil {
			panic(err)
		}
		if val == "" {
			continue
		}
		data, err := hex.DecodeString(val)
		if err != nil {
			panic(err)
		}
		op := decodeOperation(data)
		if op != nil {
			return op
		}
	}
	return nil
}

type testNetwork struct {
	parties     party.IDSlice
	msgChannels map[party.ID]chan []byte
	mtgChannels map[party.ID]chan []byte
	mtx         sync.Mutex
}

func newTestNetwork(parties party.IDSlice) *testNetwork {
	n := &testNetwork{
		parties:     parties,
		msgChannels: make(map[party.ID]chan []byte, 2*len(parties)),
		mtgChannels: make(map[party.ID]chan []byte, 2*len(parties)),
	}
	N := len(n.parties)
	for _, id := range n.parties {
		n.msgChannels[id] = make(chan []byte, N*N)
		n.mtgChannels[id] = make(chan []byte, N*N)
	}
	return n
}

func (n *testNetwork) mtgLoop(ctx context.Context, node *Node) {
	filter := make(map[string]bool)
	loop := n.mtgChannels[node.id]
	logger.Printf("loop: %s %d", node.id, len(loop))
	for mob := range loop {
		k := hex.EncodeToString(mob)
		if filter[k] {
			continue
		}
		var out mtg.Action
		_ = json.Unmarshal(mob, &out)
		out.TestAttachActionToGroup(node.group)
		ts, asset := node.ProcessOutput(ctx, &out)
		if asset != "" {
			panic(asset)
		}
		for _, t := range ts {
			op := decodeOperation([]byte(t.Memo))
			memo := mtg.EncodeMixinExtraBase64(node.conf.AppId, []byte(t.Memo))
			err := node.store.WriteProperty(ctx, "SIGNER:"+op.Id, hex.EncodeToString([]byte(memo)))
			if err != nil {
				panic(err)
			}
		}
		filter[k] = true
	}
}

func (node *Node) mtgQueueTestOutput(ctx context.Context, memo []byte) error {
	hash := []byte{byte(node.Index())}
	hash = append(hash, memo...)
	out := &mtg.Action{
		UnifiedOutput: mtg.UnifiedOutput{
			OutputId:           uuid.Must(uuid.NewV4()).String(),
			TransactionHash:    crypto.Sha256Hash(hash).String(),
			AppId:              node.conf.AppId,
			Amount:             decimal.NewFromInt(1),
			Senders:            []string{string(node.id)},
			AssetId:            node.conf.AssetId,
			SequencerCreatedAt: time.Now().UTC(),
		},
	}
	out.Extra = mtg.EncodeMixinExtraBase64(node.conf.AppId, memo)
	out.Extra = hex.EncodeToString([]byte(out.Extra))
	data := common.MarshalJSONOrPanic(out)
	network := node.network.(*testNetwork)
	return network.QueueMTGOutput(ctx, data)
}

func (n *testNetwork) ReceiveMessage(ctx context.Context) (*messenger.MixinMessage, error) {
	id := ctx.Value(partyContextKey).(string)
	msb := <-n.msgChannel(party.ID(id))
	_, msg, _ := unmarshalSessionMessage(msb)
	return &messenger.MixinMessage{
		Peer:      string(msg.From),
		Data:      msb,
		CreatedAt: time.Now().UTC(),
	}, nil
}

func (n *testNetwork) QueueMessage(ctx context.Context, receiver string, b []byte) error {
	sessionId, msg, err := unmarshalSessionMessage(b)
	logger.Verbosef("test.QueueMessage(%s) => %x %v %v", receiver, sessionId, msg, err)
	if err != nil {
		return err
	}
	n.msgChannel(party.ID(receiver)) <- marshalSessionMessage(sessionId, msg)
	logger.Verbosef("test.Send(%s) => %x %v %v", receiver, sessionId, msg, err)
	return nil
}

func (n *testNetwork) QueueMTGOutput(ctx context.Context, b []byte) error {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	for _, c := range n.mtgChannels {
		c <- b
	}
	return nil
}

func (n *testNetwork) mtgChannel(id party.ID) chan []byte {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	return n.mtgChannels[id]
}

func (n *testNetwork) msgChannel(id party.ID) chan []byte {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	return n.msgChannels[id]
}

func getTestSystemConfirmCallMessage(signature string) string {
	if signature == "2tPHv7kbUeHRWHgVKKddQqXnjDhuX84kTyCvRy1BmCM4m4Fkq4vJmNAz8A7fXqckrSNRTAKuPmAPWnzr5T7eCChb" {
		return "4d57022c484aebdb7d4472c16740f7e8c4f9047b41cbcf05a9d517558bc276c7"
	}
	if signature == "5s3UBMymdgDHwYvuaRdq9SLq94wj5xAgYEsDDB7TQwwuLy1TTYcSf6rF4f2fDfF7PnA9U75run6r1pKm9K1nusCR" {
		return "bf1648ad15341bc4225e08e1c6842df68bf80f309764ec32327deab8e2743167"
	}
	return ""
}

var (
	testFROSTKeys1 = map[party.ID]string{
		"member-id-0": "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b;0001000b6d656d6265722d69642d3000020020fe4584dcd16c51736b64e329ef2fd51b4f1d98ee833cdc96ace16398fd243f080020fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b000000b9a46b6d656d6265722d69642d305820cd5b764c011927f356938f5ebdd5f825c6f07e72f07a67ab7da1b8ec291de8d56b6d656d6265722d69642d315820d059874222f3d7a00a98da49fe388141717541f7d6ba7b0baf01af63c03510796b6d656d6265722d69642d325820e8b3ba906961e5e2ab66405d7105c2b2c19695a34ae77e229dabc2ef59ec71386b6d656d6265722d69642d33582090115b147e3977a8d44f58d40cdece998bd4b204b02ad91da9756cfff9969298",
		"member-id-1": "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b;0001000b6d656d6265722d69642d3100020020c6ec44a22c007a43d7518ac10669424693b159534fa32dbe872a5169c8f7210c0020fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b000000b9a46b6d656d6265722d69642d305820cd5b764c011927f356938f5ebdd5f825c6f07e72f07a67ab7da1b8ec291de8d56b6d656d6265722d69642d315820d059874222f3d7a00a98da49fe388141717541f7d6ba7b0baf01af63c03510796b6d656d6265722d69642d325820e8b3ba906961e5e2ab66405d7105c2b2c19695a34ae77e229dabc2ef59ec71386b6d656d6265722d69642d33582090115b147e3977a8d44f58d40cdece998bd4b204b02ad91da9756cfff9969298",
		"member-id-2": "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b;0001000b6d656d6265722d69642d3200020020e6543b705f73a02061f97cdcc45a47934dc5ee9f7a9f382d417eb74128ea100f0020fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b000000b9a46b6d656d6265722d69642d305820cd5b764c011927f356938f5ebdd5f825c6f07e72f07a67ab7da1b8ec291de8d56b6d656d6265722d69642d315820d059874222f3d7a00a98da49fe388141717541f7d6ba7b0baf01af63c03510796b6d656d6265722d69642d325820e8b3ba906961e5e2ab66405d7105c2b2c19695a34ae77e229dabc2ef59ec71386b6d656d6265722d69642d33582090115b147e3977a8d44f58d40cdece998bd4b204b02ad91da9756cfff9969298",
		"member-id-3": "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b;0001000b6d656d6265722d69642d330002002071aa71e94f63b2b232bec3d74a0b05ee7d5857d40531fde3d8dc96211dfc0b010020fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b000000b9a46b6d656d6265722d69642d305820cd5b764c011927f356938f5ebdd5f825c6f07e72f07a67ab7da1b8ec291de8d56b6d656d6265722d69642d315820d059874222f3d7a00a98da49fe388141717541f7d6ba7b0baf01af63c03510796b6d656d6265722d69642d325820e8b3ba906961e5e2ab66405d7105c2b2c19695a34ae77e229dabc2ef59ec71386b6d656d6265722d69642d33582090115b147e3977a8d44f58d40cdece998bd4b204b02ad91da9756cfff9969298",
	}
	testFROSTKeys2 = map[party.ID]string{
		"member-id-0": "4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295;0001000b6d656d6265722d69642d3000020020d9eb970a228a541283bf1378a94cde85179c574c92e6dfdcb510a274921c260800204375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca850029500205030d34432d9323e0bb0d4f83d26565f78ea5bdde762050ea7962c37ff7eb02400b9a46b6d656d6265722d69642d3058200c936db9dd8f705ab3395b21f97118ddaa58ded4ec63367bda2b258fbba0f37e6b6d656d6265722d69642d3158202a63eb53d93f05be548f7e483b66981fe98285407423a239a11b366b290390736b6d656d6265722d69642d325820399b5242e0b9bc8c8e793e63c538c1f37a45110bd0ccd3bf3b7e7a9644bfd7f66b6d656d6265722d69642d335820b57cdb2507ce3b7eef97e6c14ab0ebfa7a6b42dab0de7573e4db5d3fa5bcae37",
		"member-id-1": "4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295;0001000b6d656d6265722d69642d310002002024d226e5c362ec4a3d670e389b5a7af77acb3e3c73ed8c171706cab242e6260f00204375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca850029500205030d34432d9323e0bb0d4f83d26565f78ea5bdde762050ea7962c37ff7eb02400b9a46b6d656d6265722d69642d3058200c936db9dd8f705ab3395b21f97118ddaa58ded4ec63367bda2b258fbba0f37e6b6d656d6265722d69642d3158202a63eb53d93f05be548f7e483b66981fe98285407423a239a11b366b290390736b6d656d6265722d69642d325820399b5242e0b9bc8c8e793e63c538c1f37a45110bd0ccd3bf3b7e7a9644bfd7f66b6d656d6265722d69642d335820b57cdb2507ce3b7eef97e6c14ab0ebfa7a6b42dab0de7573e4db5d3fa5bcae37",
		"member-id-2": "4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295;0001000b6d656d6265722d69642d3200020020a15b5382d54a354e943e5fe090f0ee260c64a6ddd4f85a9ee7c6a608893d780800204375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca850029500205030d34432d9323e0bb0d4f83d26565f78ea5bdde762050ea7962c37ff7eb02400b9a46b6d656d6265722d69642d3058200c936db9dd8f705ab3395b21f97118ddaa58ded4ec63367bda2b258fbba0f37e6b6d656d6265722d69642d3158202a63eb53d93f05be548f7e483b66981fe98285407423a239a11b366b290390736b6d656d6265722d69642d325820399b5242e0b9bc8c8e793e63c538c1f37a45110bd0ccd3bf3b7e7a9644bfd7f66b6d656d6265722d69642d335820b57cdb2507ce3b7eef97e6c14ab0ebfa7a6b42dab0de7573e4db5d3fa5bcae37",
		"member-id-3": "4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295;0001000b6d656d6265722d69642d33000200203d5c133f71a541745ee2fd1369081b29cb658e30b7084a712753387665221a0400204375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca850029500205030d34432d9323e0bb0d4f83d26565f78ea5bdde762050ea7962c37ff7eb02400b9a46b6d656d6265722d69642d3058200c936db9dd8f705ab3395b21f97118ddaa58ded4ec63367bda2b258fbba0f37e6b6d656d6265722d69642d3158202a63eb53d93f05be548f7e483b66981fe98285407423a239a11b366b290390736b6d656d6265722d69642d325820399b5242e0b9bc8c8e793e63c538c1f37a45110bd0ccd3bf3b7e7a9644bfd7f66b6d656d6265722d69642d335820b57cdb2507ce3b7eef97e6c14ab0ebfa7a6b42dab0de7573e4db5d3fa5bcae37",
	}
)
