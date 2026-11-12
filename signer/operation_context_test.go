package signer

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

type operationPanicNetwork struct {
	Network
	cancel context.CancelFunc
	value  any
}

func (n operationPanicNetwork) QueueMessage(context.Context, string, []byte) error {
	if n.cancel != nil {
		n.cancel()
	}
	panic(n.value)
}

func TestRunOperationOnlyRecoversCancellation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cancel  bool
		value   any
		recover bool
	}{
		{"cancellation", true, context.Canceled, true},
		{"wrapped cancellation", true, fmt.Errorf("write: %w", context.Canceled), true},
		{"canceled transaction", true, sql.ErrTxDone, true},
		{"unrelated error", true, errors.New("network failed"), false},
		{"non-error panic", true, "invalid operation", false},
		{"live context", false, context.Canceled, false},
		{"unexpected rollback", false, sql.ErrTxDone, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			network := operationPanicNetwork{value: tc.value}
			if tc.cancel {
				network.cancel = cancel
			}
			conf := &mtg.Configuration{}
			conf.Genesis.Members = []string{"sender", "receiver"}
			node := &Node{
				id: "sender", threshold: 1, conf: &Configuration{MTG: conf},
				network: network, mutex: new(sync.Mutex), sessions: make(map[string]*MultiPartySession),
			}
			op := &common.Operation{Id: uuid.Must(uuid.NewV4()).String(), Type: common.OperationTypeKeygenInput, Curve: common.CurveEdwards25519Default}
			run := func() { require.ErrorIs(t, node.runOperation(ctx, op, nil), context.Canceled) }
			if tc.recover {
				run()
			} else {
				require.PanicsWithValue(t, tc.value, run)
			}
		})
	}
}

func TestQueueOperationReturnsNormalResults(t *testing.T) {
	for _, member := range []bool{false, true} {
		t.Run(fmt.Sprint(member), func(t *testing.T) {
			node := &Node{id: "signer", mutex: new(sync.Mutex), operations: make(map[string]bool)}
			op := &common.Operation{Id: uuid.Must(uuid.NewV4()).String(), Type: common.OperationTypeSignInput}
			var members []party.ID
			if member {
				members = []party.ID{node.id}
			}
			result := node.queueOperation(t.Context(), op, members)
			node.operationWorkers.Wait()
			select {
			case err := <-result:
				if member {
					require.ErrorContains(t, err, "invalid fingerprint")
				} else {
					require.NoError(t, err)
				}
			default:
				t.Fatal("operation finished without sending its result")
			}
		})
	}
}

func TestQueuedOperationsFinishOnFixtureCancellation(t *testing.T) {
	var results []<-chan error
	t.Run("fixture", func(t *testing.T) {
		ctx, nodes, _ := TestPrepare(t)
		id := uuid.Must(uuid.NewV4()).String()
		op := common.Operation{Id: id, Type: common.OperationTypeKeygenInput, Curve: common.CurveEdwards25519Default}
		for _, node := range nodes {
			require.NoError(t, node.store.WriteSessionIfNotExist(ctx, &op, crypto.Sha256Hash([]byte(id)), 0, time.Now(), false))
		}

		store := nodes[0].store
		store.db.SetMaxOpenConns(1)
		conn, err := store.db.Conn(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, conn.Close()) })
		for _, node := range nodes {
			operation := op
			results = append(results, node.queueOperation(ctx, &operation, node.GetPartySlice()))
		}

		// Hold the connection until a session read and protocol write contend
		// for the store, then end the test with the operation still in flight.
		require.Eventually(t, func() bool {
			if store.db.Stats().WaitCount == 0 {
				return false
			}
			if !store.mutex.TryRLock() {
				return true
			}
			store.mutex.RUnlock()
			return false
		}, 2*time.Second, time.Millisecond)
	})

	// Fixture cleanup has canceled the context and waited for every worker.
	for _, result := range results {
		select {
		case err := <-result:
			require.ErrorIs(t, err, context.Canceled)
		default:
			t.Fatal("operation finished without sending its cancellation result")
		}
		require.Empty(t, result)
	}
}
