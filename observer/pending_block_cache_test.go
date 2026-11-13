package observer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPendingEthereumBlockCacheReorgAndRetry(t *testing.T) {
	var branch atomic.Int64
	var failTrace, reorgDuringScan atomic.Bool
	var readsMu sync.Mutex
	reads := make(map[string][]int64)
	blockHash := func(height int64) string {
		version := int64(0)
		switch height {
		case 100:
			version = branch.Load()
		case 99:
			version = min(branch.Load(), 1)
		}
		return fmt.Sprintf("block-%d-%d", height, version)
	}
	rpc := pendingDepositsRPC(t, func(method string, params []json.RawMessage) any {
		if method == "eth_blockNumber" {
			return "0x64"
		}
		var height string
		if method == "eth_getLogs" {
			var filter struct {
				FromBlock string `json:"fromBlock"`
			}
			assert.NoError(t, json.Unmarshal(params[0], &filter))
			height = filter.FromBlock
		} else {
			assert.NoError(t, json.Unmarshal(params[0], &height))
		}
		number, err := strconv.ParseInt(strings.TrimPrefix(height, "0x"), 16, 64)
		assert.NoError(t, err)
		readMethod := method
		if method == "eth_getBlockByNumber" && string(params[1]) == "false" {
			readMethod = "header"
		}
		readsMu.Lock()
		reads[readMethod] = append(reads[readMethod], number)
		readsMu.Unlock()
		switch method {
		case "eth_getBlockByNumber":
			hash := blockHash(number)
			var transactions any = []string{"tx-" + hash}
			if string(params[1]) == "true" {
				transactions = []any{map[string]any{"hash": "tx-" + hash}}
			}
			return map[string]any{"number": height, "hash": hash, "parentHash": blockHash(number - 1),
				"timestamp": "0x0", "transactions": transactions}
		case "debug_traceBlockByNumber":
			if number == 99 && failTrace.Load() {
				return []*ethereum.RPCBlockCallTrace{nil}
			}
			if number == 100 && reorgDuringScan.Swap(false) {
				branch.Add(1)
			}
			return []*ethereum.RPCBlockCallTrace{{Result: &ethereum.RPCTransactionCallTrace{
				Type: "CALL", From: "0x2222222222222222222222222222222222222222",
				To: "0x1111111111111111111111111111111111111111", Value: "0xde0b6b3a7640000",
			}}}
		case "eth_getLogs":
			return []types.Log{}
		default:
			t.Errorf("unexpected method %s", method)
			return nil
		}
	})
	scan := new(pendingDepositScan)
	read := func() ([]*ethereum.Transfer, error) {
		return readPendingEthereumBlocks(t.Context(), common.SafeChainEthereum, rpc, common.SafeEthereumChainId, scan)
	}
	checkReads := func(blocks []int64, headers int) {
		t.Helper()
		readsMu.Lock()
		calls := reads
		reads = make(map[string][]int64)
		readsMu.Unlock()
		for _, method := range []string{"eth_getBlockByNumber", "debug_traceBlockByNumber"} {
			require.Equal(t, blocks, calls[method], method)
		}
		require.Len(t, calls["header"], headers)
	}

	transfers, err := read()
	require.NoError(t, err)
	require.Len(t, transfers, 4)
	checkReads([]int64{100, 99, 98, 97}, 2)
	old := scan.ethereum

	// A failed replacement must not publish a partial window or mark its
	// missing transfers as processed. Retry both replaced blocks next time.
	branch.Store(1)
	failTrace.Store(true)
	_, err = read()
	require.Error(t, err)
	require.Equal(t, old, scan.ethereum)
	checkReads([]int64{100, 99}, 1)
	failTrace.Store(false)
	transfers, err = read()
	require.NoError(t, err)
	require.Len(t, transfers, 4)
	checkReads([]int64{100, 99}, 2)
	for i, height := range []int64{100, 99, 98, 97} {
		require.Equal(t, "tx-"+blockHash(height), transfers[i].Hash)
	}
	old = scan.ethereum

	// A reorganization between the full block and trace reads must be
	// detected by the final tip check, even when all RPCs return success.
	branch.Store(2)
	reorgDuringScan.Store(true)
	_, err = read()
	require.ErrorContains(t, err, "pending block changed")
	require.Equal(t, old, scan.ethereum)
	checkReads([]int64{100}, 2)
	transfers, err = read()
	require.NoError(t, err)
	require.Equal(t, "tx-block-100-3", transfers[0].Hash)
	checkReads([]int64{100}, 2)

	again, err := read()
	require.NoError(t, err)
	require.Equal(t, transfers, again)
	checkReads(nil, 1)
}
