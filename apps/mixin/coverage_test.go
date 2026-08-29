package mixin

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/stretchr/testify/require"
)

type coverageRPCRequest struct {
	Method string `json:"method"`
	Params []any  `json:"params"`
}

func TestEd25519ChildDerivationValidation(t *testing.T) {
	require.False(t, CheckEd25519ValidChildPath(nil))
	require.False(t, CheckEd25519ValidChildPath([]byte{0, 0, 0}))
	require.True(t, CheckEd25519ValidChildPath([]byte{0, 1, 0}))

	private := crypto.NewKeyFromSeed(bytes.Repeat([]byte{1}, 64))
	public := private.Public()
	child := DeriveEd25519Child(public.String(), []byte{0, 1, 2})
	require.Len(t, child, 32)
	require.NotEqual(t, public[:], []byte(child))

	require.Panics(t, func() { DeriveEd25519Child("not-hex", []byte{1}) })
	require.Panics(t, func() { DeriveEd25519Child(strings.Repeat("0", 64), []byte{1}) })
	require.Panics(t, func() { DeriveEd25519Child(public.String(), []byte{0, 0}) })
}

func TestMixinRPCParsesTransactionsAndSnapshots(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var request coverageRPCRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case "gettransaction":
			require.Equal(t, []any{"transaction-hash"}, request.Params)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"asset":      "asset-id",
					"extra":      "extra",
					"hash":       "transaction-hash",
					"outputs":    []any{map[string]any{"type": OutputTypeWithdrawalClaim, "amount": "1", "withdrawal": map[string]any{"address": "destination", "tag": "tag"}}},
					"references": []string{"reference"},
				},
			})
		case "listsnapshots":
			require.Equal(t, []any{"7", "2", "false", "true"}, request.Params)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []any{map[string]any{
					"hash": "snapshot-hash", "hex": "00", "topology": 8,
					"transactions": []any{map[string]any{"hash": "transaction-hash"}},
				}},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{"code": -1, "message": "rejected"},
			})
		}
	}))
	t.Cleanup(server.Close)

	transaction, err := RPCGetTransaction(t.Context(), server.URL, "transaction-hash")
	require.NoError(t, err)
	require.Equal(t, "asset-id", transaction.Asset)
	require.Equal(t, "destination", transaction.Output[0].Withdrawal.Address)
	require.Equal(t, []string{"reference"}, transaction.References)

	snapshots, err := RPCListSnapshots(t.Context(), server.URL, 7, 2)
	require.NoError(t, err)
	require.Len(t, snapshots, 1)
	require.Equal(t, uint64(8), snapshots[0].Topology)
	require.Equal(t, "transaction-hash", snapshots[0].Transactions[0].Hash)

	_, err = callMixinRPC(server.URL, "rejected", nil)
	require.ErrorContains(t, err, "rejected")
}

func TestMixinRPCRejectsMalformedResponsesAndTransportErrors(t *testing.T) {
	malformed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	_, err := callMixinRPC(malformed.URL, "method", nil)
	require.ErrorContains(t, err, "invalid character")
	malformed.Close()

	wrongData := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": "not-a-transaction"})
	}))
	_, err = RPCGetTransaction(t.Context(), wrongData.URL, "hash")
	require.Error(t, err)
	_, err = RPCListSnapshots(t.Context(), wrongData.URL, 1, 1)
	require.Error(t, err)
	wrongData.Close()

	_, err = callMixinRPC("://invalid", "method", nil)
	require.Error(t, err)

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()
	_, err = callMixinRPC(closedURL, "method", nil)
	require.Error(t, err)
	require.Contains(t, buildRPCError("rpc", "method", []any{1}, errors.New("failed")).Error(), "failed")

	require.Panics(t, func() {
		_, _ = callMixinRPC("http://unused", "method", []any{func() {}})
	})
}

func TestMixinRPCRetriesTransientDecodeFailure(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte("x"))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"hash": "retried"},
		})
	}))
	t.Cleanup(server.Close)

	transaction, err := RPCGetTransaction(t.Context(), server.URL, "retried")
	require.NoError(t, err)
	require.Equal(t, "retried", transaction.Hash)
	require.Equal(t, int32(2), calls.Load())
}
