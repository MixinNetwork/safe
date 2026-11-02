package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSQLiteIterationErrorsAreReturned(t *testing.T) {
	store, err := OpenWalletSQLite3Store(t.TempDir() + "/wallet.sqlite3")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	tx, err := store.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer Rollback(tx)

	// SQLite prepares this query successfully, but fails while advancing rows.
	const query = "SELECT abs(-9223372036854775808)"
	exists, err := store.checkExistence(t.Context(), tx, query)
	require.ErrorContains(t, err, "integer overflow")
	require.False(t, exists)
	_, err = store.listOutputsByQuery(t.Context(), tx, query)
	require.ErrorContains(t, err, "integer overflow")
}
