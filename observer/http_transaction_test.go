package observer

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	keeperstore "github.com/MixinNetwork/safe/keeper/store"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestHTTPGetTransactionSignatureProgress(t *testing.T) {
	type signatureRow struct {
		input     int
		state     int
		signature any
	}
	for _, test := range []struct {
		name string
		rows []signatureRow
		want int
	}{
		{name: "no collected signatures"},
		{
			name: "pending signature is visible before completion",
			rows: []signatureRow{{0, common.RequestStatePending, "abcd"}},
			want: 1,
		},
		{
			name: "unsigned completed request is excluded",
			rows: []signatureRow{{0, common.RequestStateDone, nil}},
		},
		{
			name: "duplicate completed requests count once",
			rows: []signatureRow{
				{0, common.RequestStateDone, "abcd"},
				{0, common.RequestStateDone, "ef01"},
			},
			want: 1,
		},
		{
			name: "mixed states count distinct signed inputs",
			rows: []signatureRow{
				{0, common.RequestStatePending, "abcd"},
				{0, common.RequestStateDone, "abcd"},
				{1, common.RequestStatePending, "ef01"},
				{2, common.RequestStateInitial, nil},
				{3, common.RequestStateDone, nil},
			},
			want: 2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTransactionHTTPFixture(t)
			fixture.addSignature(t, "unrelated", "another-transaction", 99, common.RequestStateDone, "abcd")
			for i, row := range test.rows {
				fixture.addSignature(t, fmt.Sprintf("signature-%d", i), fixture.hash, row.input, row.state, row.signature)
			}

			response := fixture.get(t)
			require.Equal(t, http.StatusOK, response.Code)
			require.Equal(t, "application/json; charset=UTF-8", response.Header().Get("Content-Type"))
			want, err := json.Marshal(map[string]any{
				"account_id": fixture.accountID, "account_address": fixture.address,
				"chain": common.SafeChainEthereum, "id": fixture.requestID, "hash": fixture.hash,
				"raw": fixture.raw, "signers": []string{"holder"}, "signatures": test.want,
				// The keeper has finished its transaction, but the observer is still pending.
				"state": "pending",
			})
			require.NoError(t, err)
			require.JSONEq(t, string(want), response.Body.String())
		})
	}
}

func TestHTTPGetTransactionSpentView(t *testing.T) {
	fixture := newTransactionHTTPFixture(t)
	fixture.addSignature(t, "original", fixture.hash, 0, common.RequestStateDone, "abcd")
	fixture.addSignature(t, "spent-0", "spent-hash", 0, common.RequestStateDone, "ef01")
	fixture.addSignature(t, "spent-1", "spent-hash", 1, common.RequestStateDone, "ef01")
	_, err := fixture.node.store.db.ExecContext(t.Context(),
		"UPDATE transactions SET state=?, spent_hash=?, spent_raw=?, updated_at=? WHERE transaction_hash=?",
		common.RequestStateDone, "spent-hash", "spent-raw", time.Now().Add(-2*ethereumTransactionStuckTime), fixture.hash)
	require.NoError(t, err)

	response := fixture.get(t)
	require.Equal(t, http.StatusOK, response.Code)
	var got map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &got))
	require.Equal(t, "spent", got["state"])
	require.Equal(t, "spent-hash", got["hash"])
	require.Equal(t, "spent-raw", got["raw"])
	require.Equal(t, fixture.requestID, got["id"])
	require.Equal(t, float64(1), got["signatures"], "count signatures for the original transaction, not its broadcast hash")
}

func TestHTTPGetTransactionMissingRecordsAndStoreErrors(t *testing.T) {
	for _, test := range []struct {
		name     string
		observer bool
		query    string
		status   int
		error    string
	}{
		{"missing transaction", false, "DELETE FROM transactions", http.StatusNotFound, "transaction"},
		{"missing approval", true, "DELETE FROM transactions", http.StatusNotFound, "approval"},
		{"missing safe", false, "DELETE FROM safes", http.StatusNotFound, "safe"},
		{"missing proposal", false, "DELETE FROM safe_proposals", http.StatusNotFound, "proposal"},
		{"transaction lookup fails", false, "DROP TABLE transactions", http.StatusInternalServerError, "500"},
		{"approval lookup fails", true, "DROP TABLE transactions", http.StatusInternalServerError, "500"},
		{"safe lookup fails", false, "DROP TABLE safes", http.StatusInternalServerError, "500"},
		{"proposal lookup fails", false, "DROP TABLE safe_proposals", http.StatusInternalServerError, "500"},
		{"signature count fails", false, "DROP TABLE signature_requests", http.StatusInternalServerError, "500"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTransactionHTTPFixture(t)
			db := fixture.keeperDB
			if test.observer {
				db = fixture.node.store.db
			}
			_, err := db.ExecContext(t.Context(), test.query)
			require.NoError(t, err)

			response := fixture.get(t)
			require.Equal(t, test.status, response.Code)
			require.JSONEq(t, fmt.Sprintf(`{"error":%q}`, test.error), response.Body.String())
		})
	}
}

func TestHTTPGetTransactionRequestWithoutTransaction(t *testing.T) {
	for _, state := range []int{
		common.RequestStateInitial, common.RequestStatePending, common.RequestStateDone, common.RequestStateFailed,
	} {
		t.Run(common.StateName(state), func(t *testing.T) {
			fixture := newTransactionHTTPFixture(t)
			_, err := fixture.keeperDB.ExecContext(t.Context(), "DELETE FROM transactions")
			require.NoError(t, err)
			_, err = fixture.keeperDB.ExecContext(t.Context(), "UPDATE requests SET state=? WHERE request_id=?", state, fixture.requestID)
			require.NoError(t, err)

			response := fixture.get(t)
			if state == common.RequestStateFailed {
				require.Equal(t, http.StatusOK, response.Code)
				require.JSONEq(t, fmt.Sprintf(`{"id":%q,"state":"failed"}`, fixture.requestID), response.Body.String())
			} else {
				require.Equal(t, http.StatusNotFound, response.Code)
				require.JSONEq(t, `{"error":"transaction"}`, response.Body.String())
			}
		})
	}
}

type transactionHTTPFixture struct {
	node      *Node
	keeperDB  *sql.DB
	requestID string
	accountID string
	address   string
	hash      string
	raw       string
}

func newTransactionHTTPFixture(t *testing.T) *transactionHTTPFixture {
	t.Helper()
	path := t.TempDir() + "/keeper.sqlite3"
	db, err := common.OpenSQLite3Store(path, keeperstore.SCHEMA)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	reader, err := keeperstore.OpenSQLite3ReadOnlyStore(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reader.Close()) })
	fixture := &transactionHTTPFixture{
		node: &Node{store: coverageObserverStore(t), keeperStore: reader}, keeperDB: db,
		requestID: "0ca34767-3a70-4a28-afd9-51c9bce4ecf5",
		accountID: "49ac3214-77b7-41f0-b63f-2a139965be07",
		address:   "0x1111111111111111111111111111111111111111",
	}
	keys := make([]string, 3)
	for i := range keys {
		private, err := crypto.HexToECDSA(strings.Repeat(fmt.Sprintf("%02x", i+1), 32))
		require.NoError(t, err)
		keys[i] = hex.EncodeToString(crypto.CompressPubkey(&private.PublicKey))
	}
	transaction, err := ethereum.CreateTransaction(t.Context(), ethereum.TypeETHTx, 1, fixture.requestID,
		fixture.address, "0x2222222222222222222222222222222222222222", ethereum.EthereumEmptyAddress, "1", big.NewInt(0))
	require.NoError(t, err)
	fixture.hash = transaction.RequestHash
	unsigned := hex.EncodeToString(transaction.Marshal())
	private, err := crypto.HexToECDSA(strings.Repeat("01", 32))
	require.NoError(t, err)
	signature, err := crypto.Sign(ethereum.HashMessageForSignature(hex.EncodeToString(transaction.Message)), private)
	require.NoError(t, err)
	transaction.Signatures[0] = ethereum.ProcessSignature(signature)
	fixture.raw = hex.EncodeToString(transaction.Marshal())

	now := time.Now().UTC()
	_, err = db.ExecContext(t.Context(), `INSERT INTO requests
		(request_id, mixin_hash, mixin_index, asset_id, amount, role, action, curve, holder, extra, state, created_at, updated_at, sequence)
		VALUES (?, ?, 0, ?, '1', ?, ?, ?, ?, '', ?, ?, ?, 1)`,
		fixture.requestID, strings.Repeat("a", 64), common.SafeEthereumChainId, common.RequestRoleHolder,
		common.ActionEthereumSafeProposeTransaction, common.CurveSecp256k1ECDSAEthereum, keys[0], common.RequestStateDone, now, now)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `INSERT INTO transactions
		(transaction_hash, raw_transaction, holder, chain, asset_id, state, data, request_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, '[]', ?, ?, ?)`,
		fixture.hash, unsigned, keys[0], common.SafeChainEthereum, common.SafeEthereumChainId,
		common.RequestStateDone, fixture.requestID, now, now)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `INSERT INTO safes
		(holder, chain, signer, observer, timelock, path, address, extra, receivers, threshold, request_id, nonce, state, safe_asset_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, '', ?, '', 'receiver', 1, ?, 0, ?, 'safe-asset', ?, ?)`,
		keys[0], common.SafeChainEthereum, keys[1], keys[2], int64(time.Hour), fixture.address,
		fixture.accountID, common.RequestStateDone, now, now)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `INSERT INTO safe_proposals
		(request_id, chain, holder, signer, observer, timelock, path, address, extra, receivers, threshold, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, '', ?, '', 'receiver', 1, ?, ?)`,
		fixture.accountID, common.SafeChainEthereum, keys[0], keys[1], keys[2], int64(time.Hour), fixture.address, now, now)
	require.NoError(t, err)
	require.NoError(t, fixture.node.store.WriteTransactionApprovalIfNotExists(t.Context(), &Transaction{
		TransactionHash: fixture.hash, RawTransaction: fixture.raw, Chain: common.SafeChainEthereum,
		Holder: keys[0], Signer: keys[1], State: common.RequestStatePending, CreatedAt: now, UpdatedAt: now,
	}))
	return fixture
}

func (fixture *transactionHTTPFixture) addSignature(t *testing.T, id, hash string, input, state int, signature any) {
	t.Helper()
	now := time.Now().UTC()
	_, err := fixture.keeperDB.ExecContext(t.Context(), `INSERT INTO signature_requests
		(request_id, transaction_hash, input_index, signer, curve, message, signature, state, created_at, updated_at)
		VALUES (?, ?, ?, 'signer', ?, 'message', ?, ?, ?, ?)`,
		id, hash, input, common.CurveSecp256k1ECDSAEthereum, signature, state, now, now)
	require.NoError(t, err)
}

func (fixture *transactionHTTPFixture) get(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/transactions/"+fixture.requestID, nil).WithContext(t.Context())
	response := httptest.NewRecorder()
	fixture.node.httpGetTransaction(response, request, map[string]string{"id": fixture.requestID})
	return response
}
