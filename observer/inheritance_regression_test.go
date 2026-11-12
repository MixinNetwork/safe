package observer

import (
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
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestGetStuckTxHashRequiresCancellationProposal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Error(err)
			return
		}
		var result any
		switch q.Method {
		case "eth_blockNumber":
			result = "0x64"
		case "eth_chainId":
			result = "0x1"
		case "eth_getBlockByNumber":
			result = map[string]any{"hash": "0x" + strings.Repeat("0", 64), "number": "0x64", "timestamp": fmt.Sprintf("0x%x", time.Now().Unix()), "transactions": []string{}}
		case "eth_call":
			result = fmt.Sprintf("0x%064x", 0)
		default:
			t.Errorf("unexpected RPC %s", q.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}))
	t.Cleanup(server.Close)
	path := t.TempDir() + "/keeper.sqlite3"
	db, err := common.OpenSQLite3Store(path, keeperstore.SCHEMA)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	oldID := uuid.Must(uuid.NewV4())
	cancelID := uuid.Must(uuid.NewV4()).String()
	now := time.Now().UTC()
	_, err = db.ExecContext(t.Context(), "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?)", "old-hash", "", "holder", common.SafeChainEthereum, "asset", common.RequestStateDone, "[]", oldID.String(), now, now)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?)", "cancel-hash", "", "holder", common.SafeChainEthereum, "asset", common.RequestStateDone, "[]", cancelID, now, now)
	require.NoError(t, err)
	extra := append([]byte{common.FlagProposeCancelTransaction}, oldID.Bytes()...)
	_, err = db.ExecContext(t.Context(), "INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", cancelID, strings.Repeat("01", 32), 0, "asset", "1", common.RequestRoleHolder, common.ActionEthereumSafeProposeTransaction, common.CurveSecp256k1ECDSAEthereum, "holder", hex.EncodeToString(extra), common.RequestStateDone, now, now, 1)
	require.NoError(t, err)
	ks, err := keeperstore.OpenSQLite3Store(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ks.Close()) })
	s := coverageObserverStore(t)
	st, err := ethereum.CreateTransaction(t.Context(), ethereum.TypeETHTx, 1, oldID.String(), "0x0000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000002", ethereum.EthereumEmptyAddress, "1", big.NewInt(0))
	require.NoError(t, err)
	tx := coverageObserverTransaction("old-hash", common.RequestStateDone, common.SafeChainEthereum, now.Add(-48*time.Hour))
	tx.TransactionHash = "old-hash"
	tx.RawTransaction = hex.EncodeToString(st.Marshal())
	require.NoError(t, s.WriteTransactionApprovalIfNotExists(t.Context(), tx))
	n := &Node{store: s, keeperStore: ks, conf: &Configuration{EthereumRPC: server.URL}}
	require.Equal(t, "old-hash", n.getStuckTxHash(t.Context(), "cancel-hash"))
	// Closure payloads can resemble a valid cancellation, but are storage
	// references. They must neither cancel another transaction nor panic.
	for _, action := range []byte{common.ActionEthereumSafeCloseAccountByInheritance, common.ActionEthereumSafeCloseAccount} {
		extraSize := 32
		if action == common.ActionEthereumSafeCloseAccount {
			extraSize = 48
		}
		for _, matchesRequest := range []bool{false, true} {
			t.Run(fmt.Sprintf("action-%d/matches-request-%t", action, matchesRequest), func(t *testing.T) {
				ref := make([]byte, extraSize)
				ref[0] = common.FlagProposeCancelTransaction
				if matchesRequest {
					copy(ref[1:], oldID.Bytes())
				}
				_, err := db.ExecContext(t.Context(), "UPDATE requests SET role=?,action=?,extra=? WHERE request_id=?",
					common.RequestRoleObserver, action, hex.EncodeToString(ref), cancelID)
				require.NoError(t, err)
				require.NotPanics(t, func() {
					require.Empty(t, n.getStuckTxHash(t.Context(), "cancel-hash"))
				})
			})
		}
	}
}
