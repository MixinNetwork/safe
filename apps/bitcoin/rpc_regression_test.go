package bitcoin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBitcoinRPCRejectsMissingInputsAndOutputs(t *testing.T) {
	for _, tx := range []*RPCTransaction{nil, {}, {Vin: []*rpcIn{nil}}} {
		_, err := RPCGetTransactionSender(ChainBitcoin, "", tx)
		require.Error(t, err)
	}
	_, _, err := RPCGetTransactionOutput(ChainBitcoin, "", "hash", -1)
	require.Error(t, err)
	for _, tc := range []struct {
		name    string
		outputs []*rpcOut
		index   int64
	}{
		{"negative previous index", []*rpcOut{{ScriptPubKey: &scriptPubKey{Address: "address"}}}, -1},
		{"out of range", nil, 0},
		{"null output", []*rpcOut{nil}, 0},
		{"missing script", []*rpcOut{{}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request bitcoinRPCTestRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					return
				}
				_ = json.NewEncoder(w).Encode(bitcoinRPCTestResponse{JSONRPC: "2.0", ID: request.ID, Result: &RPCTransaction{Vout: tc.outputs}})
			}))
			t.Cleanup(server.Close)
			_, err := RPCGetTransactionSender(ChainLitecoin, server.URL, &RPCTransaction{Vin: []*rpcIn{{TxId: "previous", VOUT: tc.index}}})
			require.Error(t, err)
			if tc.index == 0 && len(tc.outputs) > 0 {
				_, _, err = RPCGetTransactionOutput(ChainLitecoin, server.URL, "hash", 0)
				require.Error(t, err)
			}
		})
	}
}

func TestBlockAverageFeeHandlesNoUsableTransactions(t *testing.T) {
	for _, tc := range []struct {
		name         string
		transactions []*RPCTransaction
		want         int64
		wantError    bool
	}{
		{"empty", nil, 0, false},
		{"zero size", []*RPCTransaction{{VSize: 0, Fee: 1}}, 0, false},
		{"negative size", []*RPCTransaction{{VSize: -1, Fee: 1}}, 0, false},
		{"mixed sizes", []*RPCTransaction{{VSize: 0, Fee: 1}, {VSize: 100, Fee: 0.00001}}, 10, false},
		{"null transaction", []*RPCTransaction{nil}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request bitcoinRPCTestRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					return
				}
				var result any
				switch request.Method {
				case "getblockchaininfo":
					result = map[string]any{"blocks": 42}
				case "getblockhash":
					result = "hash"
				case "getblock":
					result = &RPCBlockWithTransactions{Height: 42, Hash: "hash", Tx: tc.transactions}
				default:
					t.Errorf("unexpected RPC method %s", request.Method)
				}
				_ = json.NewEncoder(w).Encode(bitcoinRPCTestResponse{JSONRPC: "2.0", ID: request.ID, Result: result})
			}))
			t.Cleanup(server.Close)
			fee, err := RPCGetBlockAverageFeePerBytes(ChainBitcoin, server.URL)
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, fee.Int64())
		})
	}
}
