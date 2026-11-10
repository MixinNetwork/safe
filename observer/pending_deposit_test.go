package observer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	ec "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPPendingDepositsRejectsInvalidChains(t *testing.T) {
	node := &Node{}
	for _, chain := range []string{"", "0", "3", "-1", "257", "262", "bitcoin", "2x"} {
		r := httptest.NewRequest(http.MethodGet, "/deposits/pending?chain="+chain, nil)
		w := httptest.NewRecorder()
		node.httpListPendingDeposits(w, r, nil)
		require.Equal(t, http.StatusBadRequest, w.Code, chain)
		require.JSONEq(t, `{"error":"chain"}`, w.Body.String())
	}
}

func TestHTTPPendingBitcoinDeposits(t *testing.T) {
	for _, chain := range []byte{common.SafeChainBitcoin, common.SafeChainLitecoin} {
		t.Run(fmt.Sprint(chain), func(t *testing.T) {
			f := newPendingDepositsHTTPFixture(t, chain)
			output := func(index int, amount float64, address string) map[string]any {
				script := map[string]any{"type": "witness_v0_scripthash", "address": address}
				if chain == common.SafeChainLitecoin {
					delete(script, "address")
					script["addresses"] = []string{address}
				}
				return map[string]any{"n": index, "value": amount, "scriptPubKey": script}
			}
			txs := map[string]any{
				"mempool": map[string]any{"txid": "mempool", "vin": []any{map[string]any{"txid": "parent", "vout": 0}},
					"vout": []any{output(0, 1, f.address), output(1, 2, f.address), output(2, 4, "untracked"), output(3, 0.00001, f.address)}},
				"block": map[string]any{"txid": "block", "vin": []any{map[string]any{"txid": "parent", "vout": 0}},
					"vout": []any{output(0, 3, f.address), output(1, 4, f.address)}},
				"parent": map[string]any{"txid": "parent", "vout": []any{output(0, 10, "sender")}},
			}
			addProcessedPendingDeposit(t, f, chain, "block", 1)
			var empty atomic.Bool
			var mempoolCalls, blockCalls atomic.Int32
			rpc := pendingDepositsRPC(t, func(method string, params []json.RawMessage) any {
				switch method {
				case "getrawmempool":
					mempoolCalls.Add(1)
					if empty.Load() {
						return map[string]any{}
					}
					return map[string]any{"mempool": map[string]any{"time": 1}}
				case "getrawtransaction":
					var hash string
					assert.NoError(t, json.Unmarshal(params[0], &hash))
					assert.Contains(t, txs, hash)
					return txs[hash]
				case "getblockchaininfo":
					return map[string]any{"blocks": 100}
				case "getblockhash":
					assert.JSONEq(t, `100`, string(params[0]))
					return "tip"
				case "getblock":
					blockCalls.Add(1)
					assert.JSONEq(t, `"tip"`, string(params[0]))
					transactions := []any{}
					if !empty.Load() {
						// A transaction can be mined between the mempool and block reads.
						transactions = []any{txs["mempool"], txs["block"]}
					}
					return map[string]any{"hash": "tip", "height": 100, "tx": transactions}
				default:
					t.Errorf("unexpected RPC method %s", method)
					return nil
				}
			})
			f.node.conf.BitcoinRPC, f.node.conf.LitecoinRPC = rpc, rpc
			before := getPendingDepositsHTTP(t, f, chain, "", false)
			require.Empty(t, getPendingDepositsHTTP(t, f, chain, "", true))
			require.NoError(t, f.node.cachePendingDeposits(t.Context(), chain, nil))
			deposits := getPendingDepositsHTTP(t, f, chain, "", true)
			require.Len(t, deposits, 3)
			for i, amount := range []string{"1", "2", "3"} {
				require.Equal(t, amount, deposits[i]["amount"])
				require.Equal(t, "sender", deposits[i]["sender"])
				require.Equal(t, "pending", deposits[i]["state"])
				require.Equal(t, common.SafeChainAssetId(chain), deposits[i]["asset_id"])
			}
			require.Equal(t, deposits[0]["transaction_hash"], deposits[1]["transaction_hash"])
			require.NotEqual(t, deposits[0]["output_index"], deposits[1]["output_index"])
			require.Empty(t, getPendingDepositsHTTP(t, f, chain, "unknown-holder", true))
			empty.Store(true)
			require.Equal(t, deposits, getPendingDepositsHTTP(t, f, chain, "", true))
			require.NoError(t, f.node.cachePendingDeposits(t.Context(), chain, nil))
			require.Empty(t, getPendingDepositsHTTP(t, f, chain, "", true))
			require.Equal(t, int32(2), mempoolCalls.Load())
			require.Equal(t, int32(2), blockCalls.Load())
			require.Equal(t, before, getPendingDepositsHTTP(t, f, chain, "", false))
		})
	}
}

func TestHTTPPendingEthereumDeposits(t *testing.T) {
	for _, chain := range []byte{common.SafeChainEthereum, common.SafeChainPolygon} {
		t.Run(fmt.Sprint(chain), func(t *testing.T) {
			f := newPendingDepositsHTTPFixture(t, chain)
			const sender = "0x2222222222222222222222222222222222222222"
			const token = "0x3333333333333333333333333333333333333333"
			hash := "0x" + strings.Repeat("a", 64)
			addProcessedPendingDeposit(t, f, chain, hash, 1)
			var empty atomic.Bool
			rpc := pendingDepositsRPC(t, func(method string, params []json.RawMessage) any {
				switch method {
				case "eth_blockNumber":
					return "0x64"
				case "eth_getBlockByNumber":
					assert.JSONEq(t, `"0x64"`, string(params[0]))
					transactions := []any{}
					if !empty.Load() {
						transactions = []any{map[string]any{"hash": hash}}
					}
					return map[string]any{"number": "0x64", "hash": "tip", "transactions": transactions}
				case "debug_traceBlockByNumber":
					assert.JSONEq(t, `"0x64"`, string(params[0]))
					if empty.Load() {
						return []*ethereum.RPCBlockCallTrace{}
					}
					return []*ethereum.RPCBlockCallTrace{{Result: &ethereum.RPCTransactionCallTrace{
						Type: "CALL", From: sender, To: f.address, Value: "0xde0b6b3a7640000",
						Calls: []*ethereum.RPCTransactionCallTrace{
							{Type: "CALL", From: sender, To: f.address, Value: "0xde0b6b3a7640000"}, // Already processed.
							{Type: "CALL", From: sender, To: f.address, Value: "0x1bc16d674ec80000"},
							{Type: "CALL", From: sender, To: f.address, Value: "0xde0b6b3a7640000", Error: "execution reverted"},
							{Type: "CALL", From: sender, To: sender, Value: "0xde0b6b3a7640000"}, // Not a safe.
						},
					}}}
				case "eth_getLogs":
					var filter map[string]any
					assert.NoError(t, json.Unmarshal(params[0], &filter))
					assert.Equal(t, "0x64", filter["fromBlock"])
					assert.Equal(t, "0x64", filter["toBlock"])
					if empty.Load() {
						return []types.Log{}
					}
					return []types.Log{{Address: ec.HexToAddress(token), TxHash: ec.HexToHash(hash), Index: 2,
						Topics: []ec.Hash{crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)")), ec.HexToHash(sender), ec.HexToHash(f.address)},
						Data:   ec.LeftPadBytes(big.NewInt(1234567).Bytes(), 32)}}
				case "eth_call":
					var call map[string]string
					assert.NoError(t, json.Unmarshal(params[0], &call))
					if call["input"] == "0x313ce567" || call["data"] == "0x313ce567" {
						return fmt.Sprintf("0x%064x", 6)
					}
					return fmt.Sprintf("0x%064x%064x", 32, 4) + hex.EncodeToString([]byte("TEST")) + strings.Repeat("0", 56)
				default:
					t.Errorf("unexpected RPC method %s (EVM mempools must not be queried)", method)
					return nil
				}
			})
			f.node.conf.EthereumRPC, f.node.conf.PolygonRPC = rpc, rpc
			before := getPendingDepositsHTTP(t, f, chain, "", false)
			require.Empty(t, getPendingDepositsHTTP(t, f, chain, "", true))
			require.NoError(t, f.node.cachePendingDeposits(t.Context(), chain, nil))
			safe, err := f.node.keeperStore.ReadSafeByAddress(t.Context(), f.address)
			require.NoError(t, err)
			deposits := getPendingDepositsHTTP(t, f, chain, safe.Holder, true)
			require.Len(t, deposits, 3)
			for i, amount := range []string{"1", "2", "1.234567"} {
				require.Equal(t, amount, deposits[i]["amount"])
				require.Equal(t, sender, deposits[i]["sender"])
				require.Equal(t, "pending", deposits[i]["state"])
			}
			require.Equal(t, common.SafeChainAssetId(chain), deposits[0]["asset_id"])
			require.Equal(t, ethereum.GenerateAssetId(chain, token), deposits[2]["asset_id"])
			require.Equal(t, float64(math.MaxInt32+2), deposits[2]["output_index"])
			require.Empty(t, getPendingDepositsHTTP(t, f, chain, "unknown-holder", true))
			empty.Store(true)
			require.Equal(t, deposits, getPendingDepositsHTTP(t, f, chain, "", true))
			require.NoError(t, f.node.cachePendingDeposits(t.Context(), chain, nil))
			require.Empty(t, getPendingDepositsHTTP(t, f, chain, "", true))
			require.Equal(t, before, getPendingDepositsHTTP(t, f, chain, "", false))
		})
	}
}

func TestPendingDepositsCachePreservedOnRPCFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "RPC unavailable", http.StatusBadRequest)
	}))
	defer server.Close()
	for _, chain := range []byte{common.SafeChainBitcoin, common.SafeChainLitecoin, common.SafeChainEthereum, common.SafeChainPolygon} {
		f := newPendingDepositsHTTPFixture(t, chain)
		f.node.conf.BitcoinRPC, f.node.conf.LitecoinRPC = server.URL, server.URL
		f.node.conf.EthereumRPC, f.node.conf.PolygonRPC = server.URL, server.URL
		require.Error(t, f.node.cachePendingDeposits(t.Context(), chain, nil))
		require.Empty(t, getPendingDepositsHTTP(t, f, chain, "", true))
		key := fmt.Sprintf("pending-deposits:%d", chain)
		value := `[{"holder":"holder","view":{"transaction_hash":"cached","state":"pending"}}]`
		require.NoError(t, f.node.store.WriteCache(t.Context(), key, value))
		before := getPendingDepositsHTTP(t, f, chain, "", true)
		require.Len(t, before, 1)
		require.Error(t, f.node.cachePendingDeposits(t.Context(), chain, nil))
		require.Equal(t, before, getPendingDepositsHTTP(t, f, chain, "", true))
	}
}

func TestHTTPPendingDepositsReadsOnlyCache(t *testing.T) {
	const snapshot = `[{"holder":"alice","view":{"transaction_hash":"a","change":true}},` +
		`{"holder":"bob","view":{"transaction_hash":"b","change":false}}]`
	for _, tc := range []struct {
		name, value, holder, want string
		chain                     byte
		expired                   bool
		status                    int
	}{
		{name: "missing", chain: common.SafeChainBitcoin, want: `[]`},
		{name: "empty", value: `[]`, chain: common.SafeChainBitcoin, want: `[]`},
		{name: "all", value: snapshot, chain: common.SafeChainBitcoin, want: `[{"transaction_hash":"a","change":true},{"transaction_hash":"b","change":false}]`},
		{name: "holder", value: snapshot, holder: "alice", chain: common.SafeChainBitcoin, want: `[{"transaction_hash":"a","change":true}]`},
		{name: "unknown holder", value: snapshot, holder: "unknown", chain: common.SafeChainBitcoin, want: `[]`},
		{name: "other chain", value: snapshot, chain: common.SafeChainLitecoin, want: `[]`},
		{name: "expired", value: snapshot, chain: common.SafeChainBitcoin, expired: true, want: `[]`},
		{name: "corrupt", value: `{`, chain: common.SafeChainBitcoin, status: http.StatusInternalServerError, want: `{"error":"500"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No RPC configuration or keeper store: the handler must only use Cache.
			node := &Node{store: coverageObserverStore(t)}
			key := fmt.Sprintf("pending-deposits:%d", common.SafeChainBitcoin)
			if tc.value != "" {
				require.NoError(t, node.store.WriteCache(t.Context(), key, tc.value))
			}
			if tc.expired {
				_, err := node.store.db.ExecContext(t.Context(), "UPDATE caches SET created_at=? WHERE key=?", time.Now().Add(-2*pendingDepositsCacheTTL), key)
				require.NoError(t, err)
			}
			node.store.db.SetMaxOpenConns(1)
			_, err := node.store.db.ExecContext(t.Context(), "PRAGMA query_only=ON")
			require.NoError(t, err)
			r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/deposits/pending?chain=%d&holder=%s", tc.chain, tc.holder), nil).WithContext(t.Context())
			w := httptest.NewRecorder()
			node.httpListPendingDeposits(w, r, nil)
			status := tc.status
			if status == 0 {
				status = http.StatusOK
			}
			require.Equal(t, status, w.Code)
			require.JSONEq(t, tc.want, w.Body.String())
		})
	}
}

func TestPendingDepositsLoopRefreshesImmediatelyAndStops(t *testing.T) {
	f := newPendingDepositsHTTPFixture(t, common.SafeChainBitcoin)
	f.node.conf.BitcoinRPC = pendingDepositsRPC(t, func(method string, params []json.RawMessage) any {
		switch method {
		case "getrawmempool":
			return map[string]any{}
		case "getblockchaininfo":
			return map[string]any{"blocks": 100}
		case "getblockhash":
			return "tip"
		case "getblock":
			return map[string]any{"hash": "tip", "height": 100, "tx": []any{}}
		default:
			t.Errorf("unexpected RPC method %s", method)
			return nil
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.node.pendingDepositsLoop(ctx, common.SafeChainBitcoin)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("pending deposit loop did not stop")
		}
	})
	require.Eventually(t, func() bool {
		value, err := f.node.store.ReadCache(t.Context(), "pending-deposits:1", pendingDepositsCacheTTL)
		return err == nil && value == "[]"
	}, time.Second, 10*time.Millisecond)
}

func TestPendingDepositsCachePreservedOnParserPanic(t *testing.T) {
	f := newPendingDepositsHTTPFixture(t, common.SafeChainEthereum)
	f.node.conf.EthereumRPC = pendingDepositsRPC(t, func(method string, params []json.RawMessage) any {
		switch method {
		case "eth_blockNumber":
			return "0x64"
		case "eth_getBlockByNumber":
			return map[string]any{"number": "0x64", "transactions": []any{map[string]any{"hash": "transaction"}}}
		case "debug_traceBlockByNumber", "eth_getLogs":
			return []any{}
		default:
			t.Errorf("unexpected RPC method %s", method)
			return nil
		}
	})
	key := fmt.Sprintf("pending-deposits:%d", common.SafeChainEthereum)
	value := `[{"holder":"holder","view":{"transaction_hash":"cached"}}]`
	require.NoError(t, f.node.store.WriteCache(t.Context(), key, value))
	var err error
	require.NotPanics(t, func() { err = f.node.cachePendingDeposits(t.Context(), common.SafeChainEthereum, nil) })
	require.Error(t, err)
	cached, err := f.node.store.ReadCache(t.Context(), key, pendingDepositsCacheTTL)
	require.NoError(t, err)
	require.Equal(t, value, cached)
}

func newPendingDepositsHTTPFixture(t *testing.T, chain byte) *transactionHTTPFixture {
	t.Helper()
	f := newTransactionHTTPFixture(t)
	_, err := f.keeperDB.ExecContext(t.Context(), "UPDATE safes SET chain=?", chain)
	require.NoError(t, err)
	params := ChainParams{TransactionMinimum: "0.0001"}
	f.node.conf = &Configuration{Bitcoin: params, Litecoin: params, Ethereum: params, Polygon: params}
	now := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, f.node.store.WritePendingDepositIfNotExists(t.Context(), &Deposit{
		TransactionHash: "existing", OutputIndex: 0, AssetId: common.SafeChainAssetId(chain), Amount: "5",
		Receiver: f.address, Holder: "holder", Chain: chain, State: common.RequestStateInitial,
		RequestId: "existing-request", CreatedAt: now, UpdatedAt: now,
	}))
	require.NoError(t, f.node.store.writeBlockCheckpoint(t.Context(), chain, 50))
	// Refreshes may write Cache, but must not modify normal deposit state.
	for _, table := range []string{"deposits", "properties", "assets", "bitcoin_outputs", "accounts", "transactions"} {
		for _, operation := range []string{"INSERT", "UPDATE", "DELETE"} {
			query := fmt.Sprintf("CREATE TRIGGER pending_read_only_%s_%s BEFORE %s ON %s BEGIN SELECT RAISE(ABORT, 'normal deposit state is read only'); END", table, operation, operation, table)
			_, err := f.node.store.db.ExecContext(t.Context(), query)
			require.NoError(t, err)
		}
	}
	return f
}

func addProcessedPendingDeposit(t *testing.T, f *transactionHTTPFixture, chain byte, hash string, index int64) {
	t.Helper()
	now := time.Now().UTC()
	_, err := f.keeperDB.ExecContext(t.Context(), `INSERT INTO deposits
		(transaction_hash,output_index,asset_id,amount,receiver,sender,state,chain,holder,category,created_at,updated_at)
		VALUES (?,?,?,'1',?,'sender',?,?,'holder',?,?,?)`, hash, index, common.SafeChainAssetId(chain), f.address,
		common.RequestStateDone, chain, common.ActionObserverHolderDeposit, now, now)
	require.NoError(t, err)
}

func getPendingDepositsHTTP(t *testing.T, f *transactionHTTPFixture, chain byte, holder string, pending bool) []map[string]any {
	t.Helper()
	path, handler := "/deposits", f.node.httpListDeposits
	if pending {
		path, handler = "/deposits/pending", f.node.httpListPendingDeposits
	}
	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("%s?chain=%d&holder=%s", path, chain, holder), nil).WithContext(t.Context())
	w := httptest.NewRecorder()
	handler(w, r, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var deposits []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &deposits))
	require.NotNil(t, deposits, "empty snapshots must be JSON arrays")
	checkpoint, err := f.node.store.ReadProperty(t.Context(), depositCheckpointKey(chain))
	require.NoError(t, err)
	require.Equal(t, "50", checkpoint)
	return deposits
}

func pendingDepositsRPC(t *testing.T, result func(string, []json.RawMessage) any) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
			ID     json.RawMessage   `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": request.ID, "result": result(request.Method, request.Params),
		}))
	}))
	t.Cleanup(server.Close)
	return server.URL
}
