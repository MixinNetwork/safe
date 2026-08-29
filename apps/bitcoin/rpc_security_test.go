package bitcoin

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

type bitcoinRPCTestRequest struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
	ID     json.RawMessage   `json:"id"`
}

type bitcoinRPCTestResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  any             `json:"result,omitempty"`
	Error   any             `json:"error,omitempty"`
	ID      json.RawMessage `json:"id"`
}

func TestBitcoinRPCClientParsesResultsAndRejectsErrors(t *testing.T) {
	const (
		blockHash       = "000000000000000000000000000000000000000000000000000000000000002a"
		transactionHash = "0000000000000000000000000000000000000000000000000000000000000042"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var request bitcoinRPCTestRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		response := bitcoinRPCTestResponse{JSONRPC: "2.0", ID: request.ID}
		switch request.Method {
		case "getblockchaininfo":
			response.Result = map[string]any{"blocks": 42}
		case "getblockhash":
			if len(request.Params) != 1 || string(request.Params[0]) != "42" {
				t.Errorf("unexpected getblockhash params: %s", request.Params)
			}
			response.Result = blockHash
		case "sendrawtransaction":
			var raw string
			if len(request.Params) != 1 || json.Unmarshal(request.Params[0], &raw) != nil {
				t.Errorf("unexpected sendrawtransaction params: %s", request.Params)
			}
			if raw == "rejected" {
				response.Error = map[string]any{"code": -26, "message": "mandatory-script-verify-flag-failed"}
			} else {
				response.Result = transactionHash
			}
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

	hash, err := RPCGetBlockHash(server.URL, height)
	require.NoError(t, err)
	require.Equal(t, blockHash, hash)

	hash, err = RPCSendRawTransaction(server.URL, "accepted")
	require.NoError(t, err)
	require.Equal(t, transactionHash, hash)

	_, err = RPCSendRawTransaction(server.URL, "rejected")
	require.ErrorContains(t, err, "mandatory-script-verify-flag-failed")
}

func TestBitcoinRPCRetriesTransientMalformedResponse(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if call == 1 {
			_, _ = w.Write([]byte("x"))
			return
		}
		var request bitcoinRPCTestRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		_ = json.NewEncoder(w).Encode(bitcoinRPCTestResponse{
			JSONRPC: "2.0",
			Result:  map[string]any{"blocks": 99},
			ID:      request.ID,
		})
	}))
	t.Cleanup(server.Close)

	height, err := RPCGetBlockHeight(server.URL)
	require.NoError(t, err)
	require.Equal(t, int64(99), height)
	require.Equal(t, int32(2), calls.Load())
}

func TestBitcoinRPCTransactionOutputBindsRawTransaction(t *testing.T) {
	const amount = int64(50_000)
	_, public := btcec.PrivKeyFromBytes([]byte{9})
	publicHash := address.Hash160(public.SerializeCompressed())
	witnessAddress, err := address.NewAddressWitnessPubKeyHash(publicHash, NetConfig(ChainBitcoin))
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(witnessAddress)
	require.NoError(t, err)

	previous := chainhash.Hash{1}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&previous, 0), nil, nil))
	tx.AddTxOut(wire.NewTxOut(amount, pkScript))
	raw, err := MarshalWiredTransaction(tx, wire.WitnessEncoding, ChainBitcoin)
	require.NoError(t, err)
	txHash := tx.TxHash().String()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request bitcoinRPCTestRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if request.Method != "getrawtransaction" {
			t.Errorf("unexpected method %q", request.Method)
		}
		result := map[string]any{
			"txid": txHash,
			"hex":  hex.EncodeToString(raw),
			"vin":  []any{map[string]any{"coinbase": "01"}},
			"vout": []any{map[string]any{
				"value": float64(amount) / ValueSatoshi,
				"n":     0,
				"scriptPubKey": map[string]any{
					"type":    ScriptPubKeyTypeWitnessKeyHash,
					"address": witnessAddress.EncodeAddress(),
				},
			}},
		}
		_ = json.NewEncoder(w).Encode(bitcoinRPCTestResponse{
			JSONRPC: "2.0",
			Result:  result,
			ID:      request.ID,
		})
	}))
	t.Cleanup(server.Close)

	_, output, err := RPCGetTransactionOutput(ChainBitcoin, server.URL, txHash, 0)
	require.NoError(t, err)
	require.NotNil(t, output)
	require.Equal(t, amount, output.Satoshi)
	require.Equal(t, witnessAddress.EncodeAddress(), output.Address)
	require.True(t, output.Coinbase)

	wrongHash := strings.Repeat("0", 64)
	_, output, err = RPCGetTransactionOutput(ChainBitcoin, server.URL, wrongHash, 0)
	require.NoError(t, err)
	require.Nil(t, output, "RPC metadata must not substitute a different raw transaction")
}

func TestBitcoinFinalizationBoundaries(t *testing.T) {
	require.False(t, CheckFinalization(0, false))
	require.True(t, CheckFinalization(1, false))
	require.False(t, CheckFinalization(99, true))
	require.True(t, CheckFinalization(100, true))
}
