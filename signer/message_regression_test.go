package signer

import (
	"context"
	"errors"
	"testing"

	"github.com/MixinNetwork/safe/messenger"
	"github.com/MixinNetwork/safe/signer/protocol"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

type scriptedMessageNetwork struct {
	messages [][]byte
	received int
	stop     error
}

func (n *scriptedMessageNetwork) ReceiveMessage(context.Context) (*messenger.MixinMessage, error) {
	if n.received == len(n.messages) {
		return nil, n.stop
	}
	data := n.messages[n.received]
	n.received++
	return &messenger.MixinMessage{Peer: "peer", Data: data}, nil
}

func (*scriptedMessageNetwork) QueueMessage(context.Context, string, []byte) error { return nil }

func TestIncomingMessagesCheckDecodeErrorBeforeLogging(t *testing.T) {
	// A valid message without an SSID is ignored after decoding. Reaching the
	// scripted receive error proves the preceding malformed messages were skipped.
	valid := marshalSessionMessage(uuid.Must(uuid.NewV4()).Bytes(), &protocol.Message{})
	network := &scriptedMessageNetwork{
		messages: [][]byte{nil, {1}, make([]byte, 16), valid},
		stop:     errors.New("end of scripted messages"),
	}
	node := &Node{network: network}
	require.PanicsWithError(t, network.stop.Error(), func() { node.acceptIncomingMessages(context.Background()) })
	require.Equal(t, len(network.messages), network.received)
}

func TestNormalizeWorksHandlesIdleDays(t *testing.T) {
	for _, tc := range []struct {
		name  string
		works []int
		want  []byte
	}{
		{"empty", nil, []byte{}},
		{"idle", []int{0, 0, 0}, []byte{0, 0, 0}},
		{"active", []int{0, 1, 2}, []byte{0, 127, 255}},
	} {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.want, normalizeWorks(tc.works)) })
	}
}
