package common

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	bot "github.com/MixinNetwork/bot-api-go-client/v3"
	mixincommon "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/fox-one/mixin-sdk-go/v3/mixinnet"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

type mixinRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f mixinRoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := f(r)
	if response != nil {
		response.Header.Set("X-Request-Id", r.Header.Get("X-Request-Id"))
	}
	return response, err
}

func mixinJSONResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestSendTransactionReusesExistingRequest(t *testing.T) {
	const id = "f9d413e9-a459-4c60-a22c-a0d9ce9f6cba"
	const member = "0ca34767-3a70-4a28-afd9-51c9bce4ecf5"
	key := crypto.NewKeyFromSeed(bytes.Repeat([]byte{7}, 64))
	client := mixin.NewFromAccessToken("test")
	client.ClientID = member
	store, err := OpenWalletSQLite3Store(t.TempDir() + "/wallet.sqlite3")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	output := buildOutput(SafeBitcoinChainId, "1", 1)
	output.KernelAssetID = mixinnet.NewHash([]byte(SafeBitcoinChainId))
	require.NoError(t, store.WriteOutputsIfNotExists(t.Context(), []*mixin.SafeUtxo{output}))
	wallet := NewMixinWallet(client, store, 0)

	var pending *mixin.SafeTransactionRequest
	var submissions int
	resty := mixin.GetRestyClient()
	previous := resty.GetClient().Transport
	t.Cleanup(func() { resty.SetTransport(previous) })
	resty.SetTransport(mixinRoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		var data any
		switch r.URL.Path {
		case "/safe/transactions/" + id:
			if pending == nil {
				return mixinJSONResponse(`{"error":{"code":404}}`), nil
			}
			data = pending
		case "/safe/keys":
			data = []any{map[string]any{"mask": key.Public().String(), "keys": []string{key.Public().String()}}}
		case "/safe/transaction/requests", "/safe/transactions":
			var inputs []*mixin.SafeTransactionRequestInput
			require.NoError(t, json.NewDecoder(r.Body).Decode(&inputs))
			require.Len(t, inputs, 1)
			if pending == nil {
				pending = &mixin.SafeTransactionRequest{RequestID: id, RawTransaction: inputs[0].RawTransaction, Amount: decimal.NewFromInt(1), State: mixin.SafeUtxoStateUnspent, Views: []mixinnet.Key{{}}}
			}
			if r.URL.Path == "/safe/transactions" {
				submissions++
				if submissions == 1 {
					return mixinJSONResponse(`{"error":{"code":500,"description":"temporary failure"}}`), nil
				}
				pending.State = mixin.SafeUtxoStateSpent
			}
			data = []*mixin.SafeTransactionRequest{pending}
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
		body, err := json.Marshal(map[string]any{"data": data})
		require.NoError(t, err)
		return mixinJSONResponse(string(body)), nil
	}))

	send := func(memo string) (*mixin.SafeTransactionRequest, error) {
		return sendTransaction(t.Context(), wallet, client, []string{member}, 1, decimal.NewFromInt(1), id, SafeBitcoinChainId, memo, nil, key.String())
	}
	_, err = send("memo")
	require.ErrorContains(t, err, "temporary failure")
	require.Equal(t, 1, submissions)
	// Pending requests are returned without submitting them again.
	result, err := send("memo")
	require.NoError(t, err)
	require.Equal(t, pending, result)
	require.Equal(t, mixin.SafeUtxoStateUnspent, result.State)
	require.Equal(t, 1, submissions)

	pending.State = mixin.SafeUtxoStateSpent
	result, err = send("memo")
	require.NoError(t, err)
	require.Equal(t, pending, result)
	require.Equal(t, mixin.SafeUtxoStateSpent, result.State)
	require.Equal(t, 1, submissions)
}

func TestCommonRetriesStopOnExpiredContext(t *testing.T) {
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	calls := map[string]func() error{
		"storage": func() error {
			_, err := CreateObjectStorageUntilSufficient(ctx, nil, nil, nil, nil, "", bot.SafeUser{})
			return err
		},
		"send": func() error {
			_, err := SendTransactionUntilSufficient(ctx, nil, nil, nil, 1, decimal.Zero, "", "", "", nil, "")
			return err
		},
		"outputs":     func() error { _, err := listUnspentUTXOsUntilSufficient(ctx, nil, nil, 1, "", 0); return err },
		"transaction": func() error { _, err := SafeReadTransactionRequestUntilSufficient(ctx, nil, ""); return err },
		"asset":       func() error { _, err := SafeReadAssetUntilSufficient(ctx, "", nil); return err },
		"assets":      func() error { _, err := SafeReadAssetsUntilSufficient(ctx, nil, nil); return err },
		"fee":         func() error { _, err := SafeReadWithdrawalFeeUntilSufficient(ctx, nil, "", "", ""); return err },
		"withdrawal":  func() error { _, err := SafeReadWithdrawalHashUntilSufficient(ctx, nil, ""); return err },
		"users":       func() error { _, err := ReadUsers(ctx, nil, nil); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) { require.ErrorIs(t, call(), context.DeadlineExceeded) })
	}
}

func TestWithdrawalFeeAndHashResponses(t *testing.T) {
	user := &bot.SafeUser{UserId: "0ca34767-3a70-4a28-afd9-51c9bce4ecf5", SessionId: "f9d413e9-a459-4c60-a22c-a0d9ce9f6cba", SessionPrivateKey: hex.EncodeToString(make([]byte, 32))}
	var response atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, response.Load().(string))
	}))
	t.Cleanup(server.Close)
	bot.SetBaseUri(server.URL)
	t.Cleanup(func() { bot.SetBaseUri(bot.DefaultApiHost) })
	for _, tc := range []struct {
		name    string
		assetID string
		want    *bot.AssetFee
	}{
		{"matching asset", "fee", &bot.AssetFee{AssetID: "fee", Amount: "2"}},
		{"fallback to first asset", "missing", &bot.AssetFee{AssetID: "other", Amount: "1"}},
	} {
		t.Run("fee/"+tc.name, func(t *testing.T) {
			response.Store(`{"data":[{"asset_id":"other","amount":"1"},{"asset_id":"fee","amount":"2"}]}`)
			fee, err := SafeReadWithdrawalFeeUntilSufficient(t.Context(), user, "asset", tc.assetID, "destination")
			require.NoError(t, err)
			require.Equal(t, tc.want, fee)
		})
	}
	t.Run("fee/not found", func(t *testing.T) {
		response.Store(`{"error":{"code":404}}`)
		fee, err := SafeReadWithdrawalFeeUntilSufficient(t.Context(), user, "asset", "fee", "destination")
		require.NoError(t, err)
		require.Nil(t, fee)
	})
	for _, tc := range []struct {
		name      string
		body      string
		wantHash  string
		wantError string
	}{
		{"confirmed", `{"data":{"receivers":[{"destination":"address","withdrawal_hash":"hash"}]}}`, "hash", ""},
		{"missing destination", `{"data":{"receivers":[{}]}}`, "", "invalid withdrawal tx"},
		{"unconfirmed", `{"data":{"receivers":[{"destination":"address"}]}}`, "", "withdrawal tx not confirmed"},
		{"rejected", `{"error":{"code":403,"description":"forbidden"}}`, "", "forbidden"},
	} {
		t.Run("hash/"+tc.name, func(t *testing.T) {
			response.Store(tc.body)
			hash, err := SafeReadWithdrawalHashUntilSufficient(t.Context(), user, "request")
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.wantHash, hash)
		})
	}
}

func TestExtraLimitStorageCapacityBoundaries(t *testing.T) {
	for _, tc := range []struct {
		amount string
		want   int
	}{
		{"0.4095", mixincommon.ExtraSizeStorageCapacity - mixincommon.ExtraSizeStorageStep},
		{"0.4096", mixincommon.ExtraSizeStorageCapacity},
		{"0.4097", mixincommon.ExtraSizeStorageCapacity},
	} {
		t.Run(tc.amount, func(t *testing.T) {
			tx := mixinnet.Transaction{Asset: mixinnet.XINAssetId, Outputs: []*mixinnet.Output{{
				Type: mixinnet.OutputTypeScript, Amount: mixinnet.IntegerFromString(tc.amount),
				Keys: []mixinnet.Key{{1}}, Script: mixinnet.Script{mixinnet.OperatorCmp, mixinnet.OperatorSum, mixinnet.Operator64},
			}}}
			require.Equal(t, tc.want, ExtraLimit(tx))
		})
	}
}
