package mtg

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/stretchr/testify/require"
)

func newShutdownTestGroup(t *testing.T) *Group {
	t.Helper()
	store, err := OpenSQLite3Store(filepath.Join(t.TempDir(), "mtg.sqlite3"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	require.NoError(t, store.WriteProperty(t.Context(), groupBootSynced, "0"))
	return &Group{
		store:      store,
		mixin:      mixin.NewFromAccessToken("test"),
		rawMembers: []string{"0ca34767-3a70-4a28-afd9-51c9bce4ecf5"},
		threshold:  1,
	}
}

func runShutdownTest(run func()) <-chan any {
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		run()
	}()
	return done
}

func requireShutdown(t *testing.T, done <-chan any) {
	t.Helper()
	select {
	case p := <-done:
		require.Nil(t, p, "group panicked during shutdown")
	case <-time.After(2 * time.Second):
		t.Fatal("group did not stop after context cancellation")
	}
}

func TestGroupRunStopsOnCanceledContext(t *testing.T) {
	for _, alreadyCanceled := range []bool{true, false} {
		name := "while waiting"
		if alreadyCanceled {
			name = "before starting"
		}
		t.Run(name, func(t *testing.T) {
			grp := newShutdownTestGroup(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if alreadyCanceled {
				cancel()
			}
			done := runShutdownTest(func() { grp.Run(ctx) })
			if !alreadyCanceled {
				time.Sleep(20 * time.Millisecond)
				cancel()
			}
			requireShutdown(t, done)
			require.False(t, grp.Synced(t.Context()))
		})
	}
}

func TestGroupRunStopsDuringOutputRequest(t *testing.T) {
	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	client := mixin.GetRestyClient()
	previous := client.BaseURL
	client.SetBaseURL(server.URL)
	t.Cleanup(func() { client.SetBaseURL(previous) })

	grp := newShutdownTestGroup(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := runShutdownTest(func() { grp.Run(ctx) })
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("group did not fetch outputs")
	}
	cancel()
	requireShutdown(t, done)
	require.False(t, grp.Synced(t.Context()))
}

func TestDrainOutputsStopsDuringCheckpointRetry(t *testing.T) {
	grp := newShutdownTestGroup(t)
	require.NoError(t, grp.store.WriteProperty(t.Context(), outputsDrainingKey, "invalid"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := runShutdownTest(func() { grp.drainOutputsFromNetwork(ctx, map[string]bool{}, 500) })
	time.Sleep(20 * time.Millisecond)
	cancel()
	requireShutdown(t, done)
}

func TestDrainOutputsRetriesNetworkErrors(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", r.Header.Get("X-Request-Id"))
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []*UnifiedOutput{}})
	}))
	t.Cleanup(server.Close)
	client := mixin.GetRestyClient()
	previous := client.BaseURL
	client.SetBaseURL(server.URL)
	t.Cleanup(func() { client.SetBaseURL(previous) })

	grp := newShutdownTestGroup(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := runShutdownTest(func() { grp.drainOutputsFromNetwork(ctx, map[string]bool{}, 500) })
	requireShutdown(t, done)
	require.NoError(t, ctx.Err())
	require.Equal(t, int32(2), calls.Load())
}
