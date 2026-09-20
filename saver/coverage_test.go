package saver

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/stretchr/testify/require"
)

type coverageCreateItemBody struct {
	Id        string           `json:"id"`
	NodeId    string           `json:"node_id"`
	SessionId string           `json:"session_id"`
	Public    string           `json:"public"`
	Share     string           `json:"share"`
	Signature crypto.Signature `json:"signature"`
}

func TestSaverStoreRoundTripAndConflicts(t *testing.T) {
	store, err := OpenSQLite3Store(t.TempDir() + "/saver.sqlite3")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	_, err = store.ReadNodePublicKey(t.Context(), "missing")
	require.ErrorIs(t, err, sql.ErrNoRows)

	private := crypto.NewKeyFromSeed(bytes.Repeat([]byte{7}, 64))
	public := private.Public()
	require.NoError(t, store.WriteNodePublicKey(t.Context(), "node-1", public.String()))
	read, err := store.ReadNodePublicKey(t.Context(), "node-1")
	require.NoError(t, err)
	require.Equal(t, public, *read)
	require.Error(t, store.WriteNodePublicKey(t.Context(), "node-1", public.String()))
	require.Error(t, store.WriteNodePublicKey(t.Context(), "node-2", public.String()))

	items, err := store.ListItemsForNode(t.Context(), "node-1")
	require.NoError(t, err)
	require.Empty(t, items)
	require.NoError(t, store.WriteItemIfNotExist(t.Context(), "item-1", "node-1", "payload"))
	require.NoError(t, store.WriteItemIfNotExist(t.Context(), "item-1", "node-1", "payload"))
	items, err = store.ListItemsForNode(t.Context(), "node-1")
	require.NoError(t, err)
	require.Equal(t, []*Item{{Id: "item-1", Data: "payload"}}, items)
	require.Panics(t, func() {
		_ = store.WriteItemIfNotExist(t.Context(), "item-1", "node-1", "different")
	})

	tx, err := store.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.Error(t, store.execOne(t.Context(), tx, "UPDATE items SET data=data WHERE id=?", "missing"))
	require.NoError(t, tx.Rollback())

	tx, err = store.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	require.Error(t, store.execOne(t.Context(), tx, "INSERT INTO missing_table VALUES (?)", "value"))
	require.NoError(t, tx.Rollback())
}

func TestSaverStoreInvalidKeyAndOpenFailure(t *testing.T) {
	_, err := OpenSQLite3Store(t.TempDir())
	require.Error(t, err)

	store, err := OpenSQLite3Store(t.TempDir() + "/invalid-key.sqlite3")
	require.NoError(t, err)
	_, err = store.db.Exec(
		"INSERT INTO tokens (node_id, public_key, created_at, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
		"invalid", "not-a-key",
	)
	require.NoError(t, err)
	_, err = store.ReadNodePublicKey(t.Context(), "invalid")
	require.Error(t, err)
	require.NoError(t, store.Close())

	_, err = store.ListItemsForNode(t.Context(), "invalid")
	require.Error(t, err)
}

func TestSaverHTTPCreateItemValidation(t *testing.T) {
	store, err := OpenSQLite3Store(t.TempDir() + "/http.sqlite3")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	private := crypto.NewKeyFromSeed(bytes.Repeat([]byte{8}, 64))
	public := private.Public()
	require.NoError(t, store.WriteNodePublicKey(t.Context(), "node-1", public.String()))
	handler := handleSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		createItem(w, r, nil)
	}), store)

	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("{"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)

	unknown := coverageCreateItemBody{Id: "unknown", NodeId: "missing"}
	response = saverCoveragePost(t, handler, unknown)
	require.Equal(t, http.StatusBadRequest, response.Code)

	invalid := coverageCreateItemBody{Id: "invalid", NodeId: "node-1"}
	response = saverCoveragePost(t, handler, invalid)
	require.Equal(t, http.StatusBadRequest, response.Code)

	valid := saverCoverageSignedBody(private, "item-http", "node-1", "session", "public", "share")
	response = saverCoveragePost(t, handler, valid)
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"id":"item-http"`)

	_, err = store.db.Exec("DROP TABLE items")
	require.NoError(t, err)
	failing := saverCoverageSignedBody(private, "store-error", "node-1", "session", "public", "share")
	response = saverCoveragePost(t, handler, failing)
	require.Equal(t, http.StatusInternalServerError, response.Code)
}

func TestSaverHTTPRootSessionAndListenError(t *testing.T) {
	response := httptest.NewRecorder()
	root(response, httptest.NewRequest(http.MethodGet, "/", nil), nil)
	require.Equal(t, http.StatusOK, response.Code)
	require.JSONEq(t, `{}`, response.Body.String())

	var gotStore *SQLite3Store
	wantStore := &SQLite3Store{}
	handler := handleSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotStore = r.Context().Value("store").(*SQLite3Store)
		w.WriteHeader(http.StatusNoContent)
	}), wantStore)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, wantStore, gotStore)
	require.Equal(t, http.StatusNoContent, response.Code)

	require.Error(t, StartHTTP(wantStore, -1))
}

func saverCoverageSignedBody(private crypto.Key, id, nodeID, sessionID, public, share string) coverageCreateItemBody {
	message := id + nodeID + sessionID + public + share
	signature := private.Sign(crypto.Sha256Hash([]byte(message)))
	return coverageCreateItemBody{
		Id: id, NodeId: nodeID, SessionId: sessionID, Public: public, Share: share, Signature: signature,
	}
}

func saverCoveragePost(t *testing.T, handler http.Handler, body coverageCreateItemBody) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	request = request.WithContext(context.WithValue(request.Context(), "coverage", true))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
