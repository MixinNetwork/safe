package computer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/messenger"
	"github.com/MixinNetwork/safe/saver"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

type partyContextTyp string

const partyContextKey = partyContextTyp("party")

func TestProcessOutput(ctx context.Context, require *require.Assertions, nodes []*Node, out *mtg.Action, sessionId string) *common.Operation {
	out.TestAttachActionToGroup(nodes[0].group)
	network := nodes[0].network.(*testNetwork)
	for i := 0; i < 4; i++ {
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
		_, m := mtg.DecodeMixinExtraHEX(val)
		op := decodeOperation(m)
		if op != nil {
			return op
		}
	}
	return nil
}

func getFreePort() int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func testStartSaver(require *require.Assertions) (*saver.SQLite3Store, int) {
	dir, err := os.MkdirTemp("", "safe-saver-test-")
	require.Nil(err)
	store, err := saver.OpenSQLite3Store(dir + "/data.sqlite3")
	require.Nil(err)
	port := getFreePort()
	go saver.StartHTTP(store, port)
	return store, port
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
	out := &mtg.Action{
		UnifiedOutput: mtg.UnifiedOutput{
			OutputId:           uuid.Must(uuid.NewV4()).String(),
			AppId:              node.conf.AppId,
			Senders:            []string{string(node.id)},
			AssetId:            node.conf.AssetId,
			SequencerCreatedAt: time.Now(),
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
		CreatedAt: time.Now(),
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

var (
	testFROSTKeys = map[party.ID]string{
		"member-id-0": "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b;0001000b6d656d6265722d69642d3000020020fe4584dcd16c51736b64e329ef2fd51b4f1d98ee833cdc96ace16398fd243f080020fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b000000b9a46b6d656d6265722d69642d305820cd5b764c011927f356938f5ebdd5f825c6f07e72f07a67ab7da1b8ec291de8d56b6d656d6265722d69642d315820d059874222f3d7a00a98da49fe388141717541f7d6ba7b0baf01af63c03510796b6d656d6265722d69642d325820e8b3ba906961e5e2ab66405d7105c2b2c19695a34ae77e229dabc2ef59ec71386b6d656d6265722d69642d33582090115b147e3977a8d44f58d40cdece998bd4b204b02ad91da9756cfff9969298",
		"member-id-1": "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b;0001000b6d656d6265722d69642d3100020020c6ec44a22c007a43d7518ac10669424693b159534fa32dbe872a5169c8f7210c0020fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b000000b9a46b6d656d6265722d69642d305820cd5b764c011927f356938f5ebdd5f825c6f07e72f07a67ab7da1b8ec291de8d56b6d656d6265722d69642d315820d059874222f3d7a00a98da49fe388141717541f7d6ba7b0baf01af63c03510796b6d656d6265722d69642d325820e8b3ba906961e5e2ab66405d7105c2b2c19695a34ae77e229dabc2ef59ec71386b6d656d6265722d69642d33582090115b147e3977a8d44f58d40cdece998bd4b204b02ad91da9756cfff9969298",
		"member-id-2": "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b;0001000b6d656d6265722d69642d3200020020e6543b705f73a02061f97cdcc45a47934dc5ee9f7a9f382d417eb74128ea100f0020fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b000000b9a46b6d656d6265722d69642d305820cd5b764c011927f356938f5ebdd5f825c6f07e72f07a67ab7da1b8ec291de8d56b6d656d6265722d69642d315820d059874222f3d7a00a98da49fe388141717541f7d6ba7b0baf01af63c03510796b6d656d6265722d69642d325820e8b3ba906961e5e2ab66405d7105c2b2c19695a34ae77e229dabc2ef59ec71386b6d656d6265722d69642d33582090115b147e3977a8d44f58d40cdece998bd4b204b02ad91da9756cfff9969298",
		"member-id-3": "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b;0001000b6d656d6265722d69642d330002002071aa71e94f63b2b232bec3d74a0b05ee7d5857d40531fde3d8dc96211dfc0b010020fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b000000b9a46b6d656d6265722d69642d305820cd5b764c011927f356938f5ebdd5f825c6f07e72f07a67ab7da1b8ec291de8d56b6d656d6265722d69642d315820d059874222f3d7a00a98da49fe388141717541f7d6ba7b0baf01af63c03510796b6d656d6265722d69642d325820e8b3ba906961e5e2ab66405d7105c2b2c19695a34ae77e229dabc2ef59ec71386b6d656d6265722d69642d33582090115b147e3977a8d44f58d40cdece998bd4b204b02ad91da9756cfff9969298",
	}
)
