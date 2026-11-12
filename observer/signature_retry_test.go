package observer

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestObserverSignatureRetryTimeout(t *testing.T) {
	for _, chain := range []byte{common.SafeChainBitcoin, common.SafeChainEthereum} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("chain-%d/recovery-%t", chain, recovery), func(t *testing.T) {
				f := signatureRetryObserverFixture(t, chain, recovery)
				var mutex sync.Mutex
				var calls []string
				// Model transactions already accepted by Mixin. Every attempted
				// send still looks up its trace ID, exposing the retry scheduling
				// without requiring a funded wallet or contacting the network.
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/safe/transactions/") {
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
						http.Error(w, "unexpected request", http.StatusBadRequest)
						return
					}
					id := strings.TrimPrefix(r.URL.Path, "/safe/transactions/")
					mutex.Lock()
					calls = append(calls, id)
					mutex.Unlock()
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-Request-Id", r.Header.Get("X-Request-Id"))
					json.NewEncoder(w).Encode(map[string]any{"data": &mixin.SafeTransactionRequest{
						RequestID: id, TransactionHash: strings.Repeat("a", 64), State: mixin.SafeUtxoStateSpent,
					}})
				}))
				t.Cleanup(server.Close)
				resty := mixin.GetRestyClient()
				previousURL := resty.BaseURL
				resty.SetBaseURL(server.URL)
				t.Cleanup(func() { resty.SetBaseURL(previousURL) })
				f.node.mixin = mixin.NewFromAccessToken("test")

				send := func() []string {
					t.Helper()
					approval, err := f.node.store.ReadTransactionApproval(t.Context(), f.hash)
					require.NoError(t, err)
					switch {
					case chain == common.SafeChainBitcoin && recovery:
						err = f.node.sendToKeeperBitcoinApproveRecoveryTransaction(t.Context(), approval)
					case chain == common.SafeChainBitcoin:
						err = f.node.sendToKeeperBitcoinApproveNormalTransaction(t.Context(), approval)
					case recovery:
						err = f.node.sendToKeeperEthereumApproveRecoveryTransaction(t.Context(), approval)
					default:
						err = f.node.sendToKeeperEthereumApproveNormalTransaction(t.Context(), approval)
					}
					require.NoError(t, err)
					mutex.Lock()
					defer mutex.Unlock()
					result := append([]string(nil), calls...)
					calls = nil
					return result
				}
				setUpdatedAt := func(at time.Time) {
					t.Helper()
					_, err := f.node.store.db.ExecContext(t.Context(), "UPDATE transactions SET updated_at=? WHERE transaction_hash=?", at, f.hash)
					require.NoError(t, err)
				}

				recent := time.Now().UTC()
				setUpdatedAt(recent)
				baseCalls := send()
				require.Len(t, baseCalls, 2, "before timeout, only storage and the original approval are retried")
				approval, err := f.node.store.ReadTransactionApproval(t.Context(), f.hash)
				require.NoError(t, err)
				require.True(t, approval.UpdatedAt.Equal(recent), "polling must not postpone the signing timeout")

				setUpdatedAt(recent.Add(-2 * keeper.SafeSignatureTimeout))
				retryCalls := send()
				require.Len(t, retryCalls, 3, "an expired approval needs a new signing request")
				require.Equal(t, baseCalls, retryCalls[:2])
				require.NotContains(t, baseCalls, retryCalls[2])
				approval, err = f.node.store.ReadTransactionApproval(t.Context(), f.hash)
				require.NoError(t, err)
				require.False(t, approval.UpdatedAt.Before(recent))
				require.Equal(t, uint8(common.RequestStatePending), approval.State)
				require.Equal(t, baseCalls, send(), "the next poll must respect the restarted timeout")

				setUpdatedAt(recent.Add(-3 * keeper.SafeSignatureTimeout))
				nextRetryCalls := send()
				require.Len(t, nextRetryCalls, 3)
				require.Equal(t, baseCalls, nextRetryCalls[:2])
				require.NotContains(t, retryCalls, nextRetryCalls[2], "successive signing attempts need distinct IDs")

				f.addSignature(t, "completed", f.hash, 0, common.RequestStateDone, strings.Repeat("aa", 64))
				setUpdatedAt(recent.Add(-4 * keeper.SafeSignatureTimeout))
				require.Empty(t, send(), "stop requesting signatures after the keeper finishes")
			})
		}
	}
}

func signatureRetryObserverFixture(t *testing.T, chain byte, recovery bool) *transactionHTTPFixture {
	t.Helper()
	f := newTransactionHTTPFixture(t)
	safe, err := f.node.keeperStore.ReadSafeByAddress(t.Context(), f.address)
	require.NoError(t, err)
	originalHash := f.hash
	if chain == common.SafeChainBitcoin {
		account, err := bitcoin.BuildWitnessScriptAccount(safe.Holder, safe.Signer, safe.Observer, time.Hour, chain)
		require.NoError(t, err)
		f.address = account.Address
		input := &bitcoin.Input{TransactionHash: strings.Repeat("b", 64), Satoshi: 100000,
			Script: account.Script, Sequence: account.Sequence, RouteBackup: recovery}
		tx, err := bitcoin.BuildPartiallySignedTransaction([]*bitcoin.Input{input}, []*bitcoin.Output{{
			Address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Satoshi: 100000,
		}}, uuid.Must(uuid.FromString(f.requestID)).Bytes(), chain)
		require.NoError(t, err)
		key := "01"
		if recovery {
			key = "03"
		}
		private, _ := btcec.PrivKeyFromBytes(common.DecodeHexOrPanic(strings.Repeat(key, 32)))
		tx = bitcoin.SignPartiallySignedTransaction(tx.Marshal(), private)
		f.raw, f.hash = hex.EncodeToString(tx.Marshal()), tx.Hash()
		now := time.Now().UTC()
		_, err = f.keeperDB.ExecContext(t.Context(), `INSERT INTO bitcoin_outputs
			(transaction_hash,output_index,address,satoshi,script,sequence,chain,state,spent_by,request_id,created_at,updated_at)
			VALUES (?,0,?,?,?,?,?,?,?,?,?,?)`, input.TransactionHash, f.address, input.Satoshi, hex.EncodeToString(account.Script), account.Sequence,
			chain, common.RequestStatePending, f.hash, f.requestID, now, now)
		require.NoError(t, err)
	} else if recovery {
		tx, err := ethereum.UnmarshalSafeTransaction(common.DecodeHexOrPanic(f.raw))
		require.NoError(t, err)
		private, err := crypto.HexToECDSA(strings.Repeat("03", 32))
		require.NoError(t, err)
		sig, err := crypto.Sign(ethereum.HashMessageForSignature(hex.EncodeToString(tx.Message)), private)
		require.NoError(t, err)
		tx.Signatures = make([][]byte, 3)
		tx.Signatures[0] = ethereum.ProcessSignature(sig)
		f.raw = hex.EncodeToString(tx.Marshal())
	}
	_, err = f.keeperDB.ExecContext(t.Context(), "UPDATE safes SET chain=?, address=? WHERE holder=?", chain, f.address, safe.Holder)
	require.NoError(t, err)
	_, err = f.keeperDB.ExecContext(t.Context(), "UPDATE transactions SET transaction_hash=?, raw_transaction=?, chain=?, state=? WHERE transaction_hash=?",
		f.hash, f.raw, chain, common.RequestStatePending, originalHash)
	require.NoError(t, err)
	_, err = f.node.store.db.ExecContext(t.Context(), "UPDATE transactions SET transaction_hash=?, raw_transaction=?, chain=? WHERE transaction_hash=?",
		f.hash, f.raw, chain, originalHash)
	require.NoError(t, err)
	if recovery {
		approval, err := f.node.store.ReadTransactionApproval(t.Context(), f.hash)
		require.NoError(t, err)
		require.NoError(t, f.node.store.WriteInitialRecoveryWithApproval(t.Context(), &Recovery{
			Address: f.address, Chain: chain, Holder: safe.Holder, Observer: safe.Observer,
			RawTransaction: f.raw, TransactionHash: f.hash, State: common.RequestStateInitial,
			CreatedAt: approval.CreatedAt, UpdatedAt: approval.UpdatedAt,
		}, approval))
	}
	f.node.conf = &Configuration{KeeperAppId: f.requestID}
	f.node.conf.App.AppId = f.accountID
	f.node.keeper = &mtg.Configuration{}
	f.node.keeper.Genesis.Members = []string{f.requestID}
	f.node.keeper.Genesis.Threshold = 1
	return f
}
