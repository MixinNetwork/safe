package signer

import (
	"testing"
	"time"

	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/stretchr/testify/require"
)

func TestDailyWorksIncludeStartOfDay(t *testing.T) {
	store, err := OpenSQLite3Store(t.TempDir() + "/signer.sqlite3")
	require.NoError(t, err)
	defer store.Close()
	begin := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	end := begin.Add(24 * time.Hour)
	for i, at := range []time.Time{begin.Add(-time.Nanosecond), begin, end.Add(-time.Nanosecond), end} {
		_, err := store.db.ExecContext(t.Context(), "INSERT INTO session_works (session_id,signer_id,round,extra,created_at) VALUES ('session','a',?,'',?)", i, at)
		require.NoError(t, err)
	}
	works, err := store.CountDailyWorks(t.Context(), []party.ID{"a"}, begin, end)
	require.NoError(t, err)
	require.Equal(t, []int{2}, works)
}
