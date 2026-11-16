package signer

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

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

func TestStartOperationPropagatesPanics(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
		value  any
	}{
		{"cancellation", true, context.Canceled},
		{"wrapped cancellation", true, fmt.Errorf("write: %w", context.Canceled)},
		{"canceled transaction", true, sql.ErrTxDone},
		{"unrelated error", true, errors.New("network failed")},
		{"non-error panic", true, "invalid operation"},
		{"live context", false, context.Canceled},
		{"unexpected rollback", false, sql.ErrTxDone},
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
			require.PanicsWithValue(t, tc.value, func() { node.startOperation(ctx, op, nil) })
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

func TestQueuedOperationCancellationPanics(t *testing.T) {
	// A queued operation's panic is fatal, so exercise it in a subprocess.
	const childEnv = "SAFE_TEST_OPERATION_CANCELLATION"
	if os.Getenv(childEnv) == "1" {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		conf := &mtg.Configuration{}
		conf.Genesis.Members = []string{"sender", "receiver"}
		node := &Node{
			id: "sender", threshold: 1, conf: &Configuration{MTG: conf},
			network: operationPanicNetwork{cancel: cancel, value: context.Canceled},
			mutex:   new(sync.Mutex), sessions: make(map[string]*MultiPartySession),
			operations: make(map[string]bool),
		}
		op := &common.Operation{Id: uuid.Must(uuid.NewV4()).String(), Type: common.OperationTypeKeygenInput, Curve: common.CurveEdwards25519Default}
		node.queueOperation(ctx, op, nil)
		node.operationWorkers.Wait()
		return
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQueuedOperationCancellationPanics$")
	child.Env = append(os.Environ(), childEnv+"=1")
	output, err := child.CombinedOutput()
	require.NoError(t, ctx.Err(), "operation subprocess timed out")
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Contains(t, string(output), "panic: context canceled")
}
