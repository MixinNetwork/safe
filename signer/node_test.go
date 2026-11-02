package signer

import (
	"context"
	"testing"
	"time"

	"github.com/MixinNetwork/safe/signer/protocol"
	"github.com/stretchr/testify/require"
)

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
