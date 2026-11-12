package signer

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/saver"
	"github.com/MixinNetwork/safe/signer/protocol"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestTestWorkerPreservesUnexpectedPanics(t *testing.T) {
	failure := errors.New("worker failed")
	for _, tc := range []struct {
		name     string
		canceled bool
		value    any
		recover  bool
	}{
		{"cancellation", true, context.Canceled, true},
		{"wrapped cancellation", true, fmt.Errorf("read: %w", context.Canceled), true},
		{"rollback after cancellation", true, sql.ErrTxDone, true},
		{"unrelated error", true, failure, false},
		{"non-error panic", true, "worker failed", false},
		{"live context", false, context.Canceled, false},
		{"unexpected rollback", false, sql.ErrTxDone, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			run := func() { testRunWorker(ctx, func(context.Context) { panic(tc.value) }) }
			if tc.recover {
				require.NotPanics(t, run)
			} else {
				require.PanicsWithValue(t, tc.value, run)
			}
		})
	}
}

func TestTestNetworkHonorsCancellation(t *testing.T) {
	for _, operation := range []string{"receive", "message", "mtg", "mtg_queue"} {
		t.Run(operation, func(t *testing.T) {
			network := newTestNetwork(party.IDSlice{"sender", "receiver"})
			ctx := context.WithValue(t.Context(), partyContextKey, "receiver")
			ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
			defer cancel()

			var run func() error
			switch operation {
			case "receive":
				run = func() error {
					_, err := network.ReceiveMessage(ctx)
					return err
				}
			case "message":
				queue := network.msgChannel("receiver")
				for len(queue) < cap(queue) {
					queue <- nil
				}
				message := marshalSessionMessage(uuid.Must(uuid.NewV4()).Bytes(), &protocol.Message{From: "sender", To: "receiver"})
				run = func() error { return network.QueueMessage(ctx, "receiver", message) }
			case "mtg":
				queue := network.mtgChannel("receiver")
				for len(queue) < cap(queue) {
					queue <- nil
				}
				run = func() error { return network.QueueMTGOutput(ctx, nil) }
			case "mtg_queue":
				network.mtgQueue <- struct{}{}
				run = func() error { return network.QueueMTGOutput(ctx, nil) }
			}

			result := make(chan error, 1)
			go func() { result <- run() }()
			select {
			case err := <-result:
				require.ErrorIs(t, err, context.DeadlineExceeded)
			case <-time.After(time.Second):
				t.Fatal("test network ignored cancellation")
			}
		})
	}
}

func TestTestPrepareUsesTestLifetime(t *testing.T) {
	var ctx context.Context
	var nodes []*Node
	var store *saver.SQLite3Store
	t.Run("fixture", func(t *testing.T) {
		ctx, nodes, store = TestPrepare(t)
		require.Equal(t, t.Context().Done(), ctx.Done())
		require.True(t, common.CheckTestEnvironment(ctx))
	})
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	for _, node := range nodes {
		_, err := node.store.ReadProperty(t.Context(), "closed")
		require.ErrorContains(t, err, "database is closed")
	}
	_, err := store.ListItemsForNode(t.Context(), string(nodes[0].id))
	require.ErrorContains(t, err, "database is closed")
}

func TestWaitOperationHonorsCancellation(t *testing.T) {
	store, err := OpenSQLite3Store(t.TempDir() + "/signer.sqlite3")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	result := make(chan *common.Operation, 1)
	go func() { result <- testWaitOperation(ctx, &Node{store: store}, "missing") }()
	select {
	case operation := <-result:
		require.Nil(t, operation)
		require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("operation wait ignored cancellation")
	}
}
