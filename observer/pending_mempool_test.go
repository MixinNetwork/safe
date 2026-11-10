package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPendingBitcoinMempoolReusesTransactionsAndDropsRemoved(t *testing.T) {
	var phase atomic.Int32
	counts := map[string]*atomic.Int32{"cached": {}, "unrelated": {}, "removed": {}, "new": {}}
	rpc := pendingDepositsRPC(t, func(method string, params []json.RawMessage) any {
		if method == "getrawmempool" {
			entries := map[string]any{"cached": map[string]any{"time": 2}, "unrelated": map[string]any{"time": 1}}
			if phase.Load() == 0 {
				entries["removed"] = map[string]any{"time": 0}
			} else {
				entries["new"] = map[string]any{"time": 3}
			}
			return entries
		}
		assert.Equal(t, "getrawtransaction", method)
		var hash string
		assert.NoError(t, json.Unmarshal(params[0], &hash))
		counts[hash].Add(1)
		address := "safe"
		if hash == "unrelated" {
			address = "new-safe"
		}
		return map[string]any{"txid": hash, "vout": []any{map[string]any{
			"scriptPubKey": map[string]any{"address": address},
		}}}
	})
	safes := map[string]*store.Safe{"safe": {Address: "safe"}}
	mempool := new(pendingBitcoinMempool)
	txs, err := readPendingBitcoinMempool(t.Context(), common.SafeChainBitcoin, rpc, safes, mempool)
	require.NoError(t, err)
	require.Len(t, txs, 2)
	require.Contains(t, mempool.transactions, "unrelated")
	require.Nil(t, mempool.transactions["unrelated"], "do not retain unrelated transaction bodies")
	phase.Store(1)
	txs, err = readPendingBitcoinMempool(t.Context(), common.SafeChainBitcoin, rpc, safes, mempool)
	require.NoError(t, err)
	require.Len(t, txs, 2)
	require.Equal(t, "new", txs[0].TxId)
	require.Equal(t, "cached", txs[1].TxId)
	require.NotContains(t, mempool.transactions, "removed")
	for hash, count := range counts {
		require.Equal(t, int32(1), count.Load(), hash)
	}
	// A newly registered safe must be checked against previously ignored outputs.
	safes = map[string]*store.Safe{"safe": {Address: "safe"}, "new-safe": {Address: "new-safe"}}
	txs, err = readPendingBitcoinMempool(t.Context(), common.SafeChainBitcoin, rpc, safes, mempool)
	require.NoError(t, err)
	require.Len(t, txs, 3)
	require.Equal(t, int32(2), counts["unrelated"].Load())
}

func TestPendingBitcoinMempoolBoundsConcurrentReads(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	var active, maximum atomic.Int32
	rpc := pendingDepositsRPC(t, func(method string, params []json.RawMessage) any {
		if method == "getrawmempool" {
			entries := make(map[string]any)
			for i := range 64 {
				entries[fmt.Sprint(i)] = map[string]any{"time": i}
			}
			return entries
		}
		count := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); count > old; old = maximum.Load() {
			if maximum.CompareAndSwap(old, count) {
				break
			}
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		var hash string
		assert.NoError(t, json.Unmarshal(params[0], &hash))
		return map[string]any{"txid": hash}
	})
	done := make(chan error, 1)
	go func() {
		_, err := readPendingBitcoinMempool(ctx, common.SafeChainBitcoin, rpc, map[string]*store.Safe{"safe": {}}, nil)
		done <- err
	}()
	require.Eventually(t, func() bool { return active.Load() == 32 }, time.Second, time.Millisecond)
	// Cancellation must stop all outstanding requests without waiting for retries.
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("mempool scan did not stop")
	}
	require.Equal(t, int32(32), maximum.Load())
}

func TestPendingBitcoinDepositSurvivesSlowUnrelatedTransactions(t *testing.T) {
	const address = "bc1qdfvsv7j7scuylat9j954q29tycugus6f5p4uhzga7qdtuckx2rfsanga3v"
	const hash = "63b09ed6cf92da615e38f7e437ca5ba05ffcaf131e858ba6fe088da7f31c1b97"
	f := newPendingDepositsHTTPFixture(t, common.SafeChainBitcoin)
	_, err := f.keeperDB.ExecContext(t.Context(), "UPDATE safes SET address=?", address)
	require.NoError(t, err)
	var unavailable atomic.Int32
	release := make(chan struct{})
	defer close(release)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
			ID     json.RawMessage   `json:"id"`
		}
		if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&request)) {
			return
		}
		var result any
		switch request.Method {
		case "getrawmempool":
			entries := map[string]any{hash: map[string]any{"time": 1}}
			for i := range 4 {
				entries[fmt.Sprintf("unavailable-%d", i)] = map[string]any{"time": i + 2}
			}
			result = entries
		case "getrawtransaction":
			var id string
			assert.NoError(t, json.Unmarshal(request.Params[0], &id))
			if strings.HasPrefix(id, "unavailable-") {
				unavailable.Add(1)
				<-release
				return
			}
			if id == hash {
				result = map[string]any{"txid": hash, "vin": []any{map[string]any{"txid": "parent", "vout": 0}},
					"vout": []any{map[string]any{"n": 0, "value": 3, "scriptPubKey": map[string]any{
						"address": address, "type": bitcoin.ScriptPubKeyTypeWitnessScriptHash,
					}}}}
			} else {
				assert.Equal(t, "parent", id)
				result = map[string]any{"txid": id, "vout": []any{map[string]any{"scriptPubKey": map[string]any{"address": "sender"}}}}
			}
		case "getblockchaininfo":
			result = map[string]any{"blocks": 100}
		case "getblockhash":
			result = "tip"
		case "getblock":
			result = map[string]any{"hash": "tip", "height": 100, "tx": []any{}}
		default:
			t.Errorf("unexpected RPC method %s", request.Method)
		}
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result}))
	}))
	t.Cleanup(server.Close)
	f.node.conf.BitcoinRPC = server.URL
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	mempool := new(pendingBitcoinMempool)
	require.NoError(t, f.node.cachePendingDeposits(ctx, common.SafeChainBitcoin, mempool))
	deposits := getPendingDepositsHTTP(t, f, common.SafeChainBitcoin, "", true)
	require.Len(t, deposits, 1)
	require.Equal(t, hash, deposits[0]["transaction_hash"])
	require.Equal(t, address, deposits[0]["receiver"])
	require.Equal(t, "3", deposits[0]["amount"])
	require.Equal(t, int32(4), unavailable.Load())
	for i := range 4 {
		require.NotContains(t, mempool.transactions, fmt.Sprintf("unavailable-%d", i), "failed reads must be retried on the next refresh")
	}
}
