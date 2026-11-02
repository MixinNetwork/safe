package common

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	bot "github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/fox-one/mixin-sdk-go/v3/mixinnet"
	"github.com/stretchr/testify/require"
)

func TestStorageRequestStates(t *testing.T) {
	const id = "f9d413e9-a459-4c60-a22c-a0d9ce9f6cba"
	const member = "0ca34767-3a70-4a28-afd9-51c9bce4ecf5"
	expected := crypto.Sha256Hash([]byte("storage transaction"))
	for _, tc := range []struct {
		name      string
		hash      string
		pending   bool
		rejected  bool
		wantError string
	}{
		{"pending then completed", expected.String(), true, false, ""},
		{"already completed", expected.String(), false, false, ""},
		{"invalid hash", "01", false, false, "invalid hash length"},
		{"permanent failure", "", false, true, "rejected storage request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var reads, creates atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Request-Id", r.Header.Get("X-Request-Id"))
				switch r.URL.Path {
				case "/safe/transactions/" + id:
					read := reads.Add(1)
					if tc.rejected {
						_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": 404}})
						return
					}
					state := "spent"
					if tc.pending && read == 1 {
						state = "unspent"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
						"request_id": id, "state": state, "transaction_hash": tc.hash,
					}})
				case "/safe/transaction/requests":
					creates.Add(1)
					var requests []*bot.KernelTransactionRequestCreateRequest
					if err := json.NewDecoder(r.Body).Decode(&requests); err != nil || len(requests) != 1 || requests[0].RequestID != id {
						t.Errorf("invalid storage request: %v %v", requests, err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if tc.rejected {
						_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
							"code": 400, "description": "rejected storage request",
						}})
						return
					}
					t.Error("existing storage request must not be created again")
					w.WriteHeader(http.StatusBadRequest)
				default:
					t.Errorf("unexpected request: %s", r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			t.Cleanup(server.Close)
			bot.SetBaseUri(server.URL)
			t.Cleanup(func() { bot.SetBaseUri(bot.DefaultApiHost) })
			resty := mixin.GetRestyClient()
			previous := resty.BaseURL
			resty.SetBaseURL(server.URL)
			t.Cleanup(func() { resty.SetBaseURL(previous) })

			client := mixin.NewFromAccessToken("test")
			client.ClientID = member
			store, err := OpenWalletSQLite3Store(t.TempDir() + "/wallet.sqlite3")
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, store.Close()) })
			extra := []byte("storage retry")
			output := buildOutput(mtg.StorageAssetId, bot.EstimateStorageCost(extra).String(), 1)
			output.KernelAssetID = mixinnet.NewHash([]byte(mtg.StorageAssetId))
			require.NoError(t, store.WriteOutputsIfNotExists(ctx, []*mixin.SafeUtxo{output}))
			key := crypto.NewKeyFromSeed(bytes.Repeat([]byte{7}, 64))
			user := bot.SafeUser{UserId: member, SessionId: id,
				SessionPrivateKey: hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), SpendPrivateKey: key.String()}
			hash, err := CreateObjectStorageUntilSufficient(ctx, NewMixinWallet(client, store, 0), client, nil, extra, id, user)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				require.Equal(t, crypto.Hash{}, hash)
			} else {
				require.NoError(t, err)
				require.Equal(t, expected, hash)
			}
			wantReads := int32(1)
			if tc.pending {
				wantReads = 2
			}
			require.Equal(t, wantReads, reads.Load())
			if tc.rejected {
				require.Equal(t, int32(1), creates.Load())
			} else {
				require.Zero(t, creates.Load())
			}
		})
	}
}
