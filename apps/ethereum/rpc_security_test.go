package ethereum

import (
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type ethereumRPCTestRequest struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
	ID     json.RawMessage   `json:"id"`
}

type ethereumRPCTestResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  any             `json:"result,omitempty"`
	Error   any             `json:"error,omitempty"`
	ID      json.RawMessage `json:"id"`
}

func TestEthereumRPCClientParsesNativeChainData(t *testing.T) {
	const (
		blockHash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		txHash    = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var request ethereumRPCTestRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		response := ethereumRPCTestResponse{JSONRPC: "2.0", ID: request.ID}
		switch request.Method {
		case "eth_blockNumber":
			response.Result = "0x2a"
		case "eth_getBlockByHash":
			response.Result = map[string]any{
				"hash":         blockHash,
				"number":       "0x2a",
				"transactions": []string{txHash},
				"timestamp":    "0x64",
			}
		case "eth_getBlockByNumber":
			if len(request.Params) != 2 || string(request.Params[0]) != `"0x2a"` {
				t.Errorf("unexpected block params: %s", request.Params)
			}
			if string(request.Params[1]) == "true" {
				response.Result = map[string]any{
					"hash":   blockHash,
					"number": "0x2a",
					"transactions": []any{map[string]any{
						"hash": txHash,
					}},
				}
			} else {
				response.Result = map[string]any{
					"hash":      blockHash,
					"number":    "0x2a",
					"timestamp": "0x64",
				}
			}
		case "eth_getTransactionByHash":
			response.Result = map[string]any{
				"blockHash":   blockHash,
				"blockNumber": "0x2a",
				"hash":        txHash,
				"from":        "0x1111111111111111111111111111111111111111",
				"to":          "0x2222222222222222222222222222222222222222",
				"value":       "0x1",
			}
		case "eth_gasPrice":
			response.Result = "0x3b9aca00"
		case "eth_getBalance":
			response.Result = "0xde0b6b3a7640000"
		case "reject":
			response.Error = map[string]any{"code": -32000, "message": "execution rejected"}
		default:
			response.Error = map[string]any{"code": -32601, "message": "method not found"}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	height, err := RPCGetBlockHeight(server.URL)
	require.NoError(t, err)
	require.Equal(t, int64(42), height)

	block, err := RPCGetBlock(server.URL, blockHash)
	require.NoError(t, err)
	require.Equal(t, uint64(42), block.Height)
	require.Equal(t, time.Unix(100, 0), block.Time)

	blockByHeight, err := RPCGetBlockByHeight(server.URL, height)
	require.NoError(t, err)
	require.Equal(t, time.Unix(100, 0), blockByHeight.Time)

	fullBlock, err := RPCGetBlockWithTransactions(server.URL, height)
	require.NoError(t, err)
	require.Equal(t, uint64(42), fullBlock.Height)
	require.Len(t, fullBlock.Tx, 1)
	require.Equal(t, blockHash, fullBlock.Tx[0].BlockHash)

	tx, err := RPCGetTransactionByHash(server.URL, txHash)
	require.NoError(t, err)
	require.Equal(t, uint64(42), tx.BlockHeight)

	gasPrice, err := RPCGetGasPrice(server.URL)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(1_000_000_000), gasPrice)

	balance, err := RPCGetAssetBalanceAtBlock(
		server.URL,
		"0x1111111111111111111111111111111111111111",
		EthereumEmptyAddress,
		42,
	)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(1_000_000_000_000_000_000), balance)

	_, err = callEthereumRPC(server.URL, "reject", nil)
	require.ErrorContains(t, err, "execution rejected")
}

func TestEthereumRPCRetriesTransientMalformedResponse(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if call == 1 {
			_, _ = w.Write([]byte("x"))
			return
		}
		var request ethereumRPCTestRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		_ = json.NewEncoder(w).Encode(ethereumRPCTestResponse{
			JSONRPC: "2.0",
			Result:  "0x63",
			ID:      request.ID,
		})
	}))
	t.Cleanup(server.Close)

	height, err := RPCGetBlockHeight(server.URL)
	require.NoError(t, err)
	require.Equal(t, int64(99), height)
	require.Equal(t, int32(2), calls.Load())
}

func TestEthereumNumberAndFinalizationBoundaries(t *testing.T) {
	value, err := ethereumNumberToUint64("0xffffffffffffffff")
	require.NoError(t, err)
	require.Equal(t, ^uint64(0), value)

	for _, invalid := range []string{
		"1",
		"0x",
		"0x10000000000000000",
		"0xnothex",
	} {
		_, err := ethereumNumberToUint64(invalid)
		require.Error(t, err, invalid)
	}

	require.False(t, CheckFinalization(0, ChainEthereum))
	require.True(t, CheckFinalization(1, ChainEthereum))
	require.False(t, CheckFinalization(255, ChainPolygon))
	require.True(t, CheckFinalization(256, ChainPolygon))
	require.Panics(t, func() { CheckFinalization(1, 0xff) })
}
