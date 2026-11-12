package signer

import (
	"context"
	"testing"
	"time"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/signer/protocol"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestSignerFixtureWorkersHonorCancellation(t *testing.T) {
	node := &Node{network: newTestNetwork(party.IDSlice{"receiver"})}
	for name, run := range map[string]func(context.Context){
		"backup":   node.loopBackup,
		"initial":  node.loopInitialSessions,
		"prepared": node.loopPreparedSessions,
		"pending":  node.loopPendingSessions,
		"incoming": node.acceptIncomingMessages,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), partyContextKey, "receiver")
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				testRunWorker(ctx, run)
			}()
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("signer worker ignored cancellation")
			}
		})
	}
}

type waitingProtocol struct {
	protocol.Handler
	started chan struct{}
}

func (h waitingProtocol) Listen() <-chan *protocol.Message {
	close(h.started)
	return nil
}

func TestSessionLoopHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	handler := waitingProtocol{started: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := (&Node{}).loopMultiPartySession(ctx, &MultiPartySession{}, handler, time.Hour)
		result <- err
	}()
	<-handler.started
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("session ignored cancellation")
	}
}

type cancelOnAcceptProtocol struct {
	protocol.Handler
	cancel context.CancelFunc
}

func (h cancelOnAcceptProtocol) CanAccept(*protocol.Message) bool { return true }

func (h cancelOnAcceptProtocol) Accept(*protocol.Message) bool {
	h.cancel()
	return true
}

func TestSessionWorkRejectsCanceledWrite(t *testing.T) {
	store, err := OpenSQLite3Store(t.TempDir() + "/signer.sqlite3")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	session := &MultiPartySession{
		id:    uuid.Must(uuid.NewV4()).Bytes(),
		round: 2,
		received: map[round.Number][]*protocol.Message{
			2: {{From: "sender", RoundNumber: 2}},
		},
	}
	require.PanicsWithValue(t, context.Canceled, func() {
		session.process(ctx, cancelOnAcceptProtocol{cancel: cancel}, store)
	})
	require.Empty(t, session.accepted)
	require.NotNil(t, session.received[2][0])
}
