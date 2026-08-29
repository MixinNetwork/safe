package bitcoin

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestBitcoinRPCAggregatesMempoolBlocksAndSenders(t *testing.T) {
	const (
		blockHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		previous  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	_, public := btcec.PrivKeyFromBytes([]byte{11})
	witnessAddress, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(public.SerializeCompressed()), NetConfig(ChainBitcoin),
	)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request bitcoinRPCTestRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		response := bitcoinRPCTestResponse{JSONRPC: "2.0", ID: request.ID}
		switch request.Method {
		case "getblockchaininfo":
			response.Result = map[string]any{"blocks": 10}
		case "getblockhash":
			response.Result = blockHash
		case "getblock":
			if len(request.Params) == 2 && string(request.Params[1]) == "2" {
				response.Result = map[string]any{
					"hash": blockHash, "height": 10,
					"tx": []any{
						map[string]any{
							"txid": "block-one", "fee": 0.000001, "vsize": 50,
							"vout": []any{map[string]any{"scriptPubKey": map[string]any{
								"addresses": []string{"legacy-one"},
							}}},
						},
						map[string]any{
							"txid": "block-two", "fee": 0.000003, "vsize": 100,
							"vout": []any{map[string]any{"scriptPubKey": map[string]any{
								"addresses": []string{"legacy-two", "extra"},
							}}},
						},
					},
				}
			} else {
				response.Result = map[string]any{
					"hash": blockHash, "height": 10, "tx": []string{"block-one"}, "confirmations": 2,
				}
			}
		case "getrawmempool":
			if len(request.Params) == 1 && string(request.Params[0]) == "true" {
				response.Result = map[string]any{
					"high": map[string]any{"fees": map[string]any{"base": 0.00001}, "vsize": 100},
					"low":  map[string]any{"fees": map[string]any{"base": 0.0000002}, "vsize": 10},
					"zero": map[string]any{"fees": map[string]any{"base": 1.0}, "vsize": 0},
				}
			} else {
				response.Result = []string{"mempool-good", "mempool-error", "mempool-malformed"}
			}
		case "getrawtransaction":
			var hash string
			require.NoError(t, json.Unmarshal(request.Params[0], &hash))
			switch hash {
			case previous:
				response.Result = map[string]any{
					"txid": previous,
					"vout": []any{map[string]any{"scriptPubKey": map[string]any{"address": witnessAddress.EncodeAddress()}}},
				}
			case "mempool-good":
				response.Result = map[string]any{"txid": hash}
			case "mempool-error":
				response.Error = map[string]any{"code": -5, "message": "not found"}
			case "mempool-malformed":
				response.Result = "not-a-transaction"
			default:
				response.Error = map[string]any{"code": -5, "message": "unknown transaction"}
			}
		default:
			response.Error = map[string]any{"code": -32601, "message": "method not found"}
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(response))
	}))
	t.Cleanup(server.Close)

	coinbase, err := RPCGetTransactionSender(ChainBitcoin, server.URL, &RPCTransaction{
		Vin: []*rpcIn{{Coinbase: "coinbase-data"}},
	})
	require.NoError(t, err)
	require.Equal(t, "coinbase-data", coinbase)
	sender, err := RPCGetTransactionSender(ChainBitcoin, server.URL, &RPCTransaction{
		Vin: []*rpcIn{{TxId: previous, VOUT: 0}},
	})
	require.NoError(t, err)
	require.Equal(t, witnessAddress.EncodeAddress(), sender)
	_, err = RPCGetTransactionSender(ChainBitcoin, server.URL, &RPCTransaction{
		Vin: []*rpcIn{{TxId: "unknown", VOUT: 0}},
	})
	require.ErrorContains(t, err, "unknown transaction")

	mempool, err := RPCGetRawMempool(ChainBitcoin, server.URL)
	require.NoError(t, err)
	require.Len(t, mempool, 1)
	require.Equal(t, "mempool-good", mempool[0].TxId)

	verboseMempool, err := RPCGetRawMempoolWithTransactions(server.URL)
	require.NoError(t, err)
	require.Len(t, verboseMempool, 3)
	average, err := RPCGetMempoolAverageFeePerBytes(server.URL)
	require.NoError(t, err)
	require.Equal(t, int64(6), average.Int64())

	block, err := RPCGetBlockWithTransactions(ChainLitecoin, server.URL, blockHash)
	require.NoError(t, err)
	require.Len(t, block.Tx, 2)
	require.Equal(t, blockHash, block.Tx[0].BlockHash)
	require.Equal(t, "legacy-one", block.Tx[0].Vout[0].ScriptPubKey.Address)
	require.Empty(t, block.Tx[1].Vout[0].ScriptPubKey.Address)
	plain := &RPCTransaction{Vout: []*rpcOut{{ScriptPubKey: &scriptPubKey{LegacyAddresses: []string{"legacy"}}}}}
	fixLitecoinLegacyScriptPubKeyRPC(ChainBitcoin, plain)
	require.Empty(t, plain.Vout[0].ScriptPubKey.Address)

	blockAverage, err := RPCGetBlockAverageFeePerBytes(ChainBitcoin, server.URL)
	require.NoError(t, err)
	require.Equal(t, int64(3), blockAverage.Int64())
	blockInfo, err := RPCGetBlock(server.URL, blockHash)
	require.NoError(t, err)
	require.Equal(t, uint64(10), blockInfo.Height)
}

func TestBitcoinEstimateAverageFeeBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		blockRate   int64
		mempoolRate int64
		chain       byte
		want        int64
		wantError   string
	}{
		{name: "minimum relay floor", blockRate: 2, mempoolRate: 2, chain: ChainBitcoin, want: 5},
		{name: "mempool wins", blockRate: 3, mempoolRate: 6, chain: ChainBitcoin, want: 6},
		{name: "litecoin range", blockRate: 4, mempoolRate: 6, chain: ChainLitecoin, want: 6},
		{name: "outside range", blockRate: 1_001, mempoolRate: 2, chain: ChainBitcoin, wantError: "CheckFeeRange"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := bitcoinCoverageFeeServer(t, test.blockRate, test.mempoolRate)
			fee, err := EstimateAvgFee(test.chain, server.URL)
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, fee)
		})
	}
}

func TestBitcoinRPCTransactionOutputConfirmedAndBoundaryRejections(t *testing.T) {
	const blockHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, public := btcec.PrivKeyFromBytes([]byte{12})
	witnessAddress, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(public.SerializeCompressed()), NetConfig(ChainBitcoin),
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(witnessAddress)
	require.NoError(t, err)
	previous := chainhash.Hash{9}
	wired := wire.NewMsgTx(2)
	wired.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&previous, 0), nil, nil))
	wired.AddTxOut(wire.NewTxOut(50_000, pkScript))
	raw, err := MarshalWiredTransaction(wired, wire.WitnessEncoding, ChainBitcoin)
	require.NoError(t, err)
	hash := wired.TxHash().String()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request bitcoinRPCTestRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		var result any
		if request.Method == "getblock" {
			result = map[string]any{"hash": blockHash, "height": 99}
		} else {
			result = map[string]any{
				"txid": hash, "blockhash": blockHash, "hex": hex.EncodeToString(raw),
				"vin": []any{map[string]any{"txid": previous.String(), "vout": 0}},
				"vout": []any{map[string]any{
					"value": 0.0005, "n": 0,
					"scriptPubKey": map[string]any{"type": ScriptPubKeyTypeWitnessKeyHash, "address": witnessAddress.EncodeAddress()},
				}},
			}
		}
		require.NoError(t, json.NewEncoder(w).Encode(bitcoinRPCTestResponse{JSONRPC: "2.0", Result: result, ID: request.ID}))
	}))
	t.Cleanup(server.Close)

	_, output, err := RPCGetTransactionOutput(ChainBitcoin, server.URL, hash, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(99), output.Height)
	_, output, err = RPCGetTransactionOutput(ChainBitcoin, server.URL, hash, 1)
	require.NoError(t, err)
	require.Nil(t, output)
}

func TestBitcoinRPCWrapperDecodeAndTransportFailures(t *testing.T) {
	wrong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request bitcoinRPCTestRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		result := any("wrong")
		if request.Method == "getblockhash" || request.Method == "sendrawtransaction" {
			result = map[string]any{"wrong": true}
		}
		_ = json.NewEncoder(w).Encode(bitcoinRPCTestResponse{JSONRPC: "2.0", Result: result})
	}))
	t.Cleanup(wrong.Close)

	_, err := RPCGetRawMempool(ChainBitcoin, wrong.URL)
	require.Error(t, err)
	_, err = RPCGetRawMempoolWithTransactions(wrong.URL)
	require.Error(t, err)
	_, err = RPCGetBlockWithTransactions(ChainBitcoin, wrong.URL, "hash")
	require.Error(t, err)
	_, err = RPCGetBlock(wrong.URL, "hash")
	require.Error(t, err)
	_, err = RPCGetBlockHash(wrong.URL, 1)
	require.Error(t, err)
	_, err = RPCGetBlockHeight(wrong.URL)
	require.Error(t, err)
	_, err = RPCSendRawTransaction(wrong.URL, "raw")
	require.Error(t, err)

	rejected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request bitcoinRPCTestRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		_ = json.NewEncoder(w).Encode(bitcoinRPCTestResponse{
			JSONRPC: "2.0",
			Error:   map[string]any{"code": -1, "message": "rejected"},
			ID:      request.ID,
		})
	}))
	t.Cleanup(rejected.Close)
	_, err = RPCGetRawMempool(ChainBitcoin, rejected.URL)
	require.ErrorContains(t, err, "rejected")
	_, err = RPCGetRawMempoolWithTransactions(rejected.URL)
	require.ErrorContains(t, err, "rejected")
	_, err = RPCGetBlockWithTransactions(ChainBitcoin, rejected.URL, "hash")
	require.ErrorContains(t, err, "rejected")
	_, err = RPCGetBlockAverageFeePerBytes(ChainBitcoin, rejected.URL)
	require.ErrorContains(t, err, "rejected")
	_, err = RPCGetMempoolAverageFeePerBytes(rejected.URL)
	require.ErrorContains(t, err, "rejected")
	_, err = EstimateAvgFee(ChainBitcoin, rejected.URL)
	require.ErrorContains(t, err, "rejected")
	_, err = RPCGetBlock(rejected.URL, "hash")
	require.ErrorContains(t, err, "rejected")
	_, err = RPCGetBlockHash(rejected.URL, 1)
	require.ErrorContains(t, err, "rejected")
	_, err = RPCGetBlockHeight(rejected.URL)
	require.ErrorContains(t, err, "rejected")

	_, err = callBitcoinRPC("://invalid", "method", nil)
	require.Error(t, err)
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()
	_, err = callBitcoinRPC(closedURL, "method", nil)
	require.Error(t, err)
	require.Contains(t, buildRPCError("rpc", "method", []any{1}, errors.New("failure")).Error(), "failure")
	require.Panics(t, func() {
		_, _ = callBitcoinRPC("http://unused", "method", []any{func() {}})
	})
}

func bitcoinCoverageFeeServer(t *testing.T, blockRate, mempoolRate int64) *httptest.Server {
	t.Helper()
	const vsize = int64(100)
	fee := func(rate int64) float64 {
		return float64(rate*vsize) / ValueSatoshi
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request bitcoinRPCTestRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		var result any
		switch request.Method {
		case "getblockchaininfo":
			result = map[string]any{"blocks": 1}
		case "getblockhash":
			result = strings.Repeat("a", 64)
		case "getblock":
			result = map[string]any{"tx": []any{map[string]any{"fee": fee(blockRate), "vsize": vsize}}}
		case "getrawmempool":
			result = map[string]any{"transaction": map[string]any{"fees": map[string]any{"base": fee(mempoolRate)}, "vsize": vsize}}
		default:
			t.Fatalf("unexpected method %q", request.Method)
		}
		require.NoError(t, json.NewEncoder(w).Encode(bitcoinRPCTestResponse{JSONRPC: "2.0", Result: result, ID: request.ID}))
	}))
	t.Cleanup(server.Close)
	return server
}
