package observer

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mixincrypto "github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	keeperstore "github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

type observerRPCTestRequest struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
	ID     json.RawMessage   `json:"id"`
}

type observerRPCTestResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  any             `json:"result,omitempty"`
	Error   any             `json:"error,omitempty"`
	ID      json.RawMessage `json:"id"`
}

func TestObserverBitcoinBroadcastRequiresExpectedHash(t *testing.T) {
	const expectedHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	raw := []byte{1, 2, 3}

	tests := []struct {
		name      string
		result    any
		rpcError  any
		wantError string
	}{
		{name: "matching hash", result: expectedHash},
		{name: "mismatched hash", result: strings.Repeat("b", 64), wantError: "malformed bitcoin transaction"},
		{
			name:     "already mined",
			rpcError: map[string]any{"code": -27, "message": "Transaction already in block chain"},
		},
		{
			name:      "consensus rejection",
			rpcError:  map[string]any{"code": -26, "message": "mandatory-script-verify-flag-failed"},
			wantError: "mandatory-script-verify-flag-failed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request observerRPCTestRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Errorf("decode request: %v", err)
					return
				}
				if request.Method != "sendrawtransaction" {
					t.Errorf("unexpected method %q", request.Method)
				}
				var sentRaw string
				if len(request.Params) != 1 || json.Unmarshal(request.Params[0], &sentRaw) != nil {
					t.Errorf("unexpected params: %s", request.Params)
				}
				if sentRaw != hex.EncodeToString(raw) {
					t.Errorf("sent raw %q", sentRaw)
				}
				_ = json.NewEncoder(w).Encode(observerRPCTestResponse{
					JSONRPC: "2.0",
					Result:  test.result,
					Error:   test.rpcError,
					ID:      request.ID,
				})
			}))
			t.Cleanup(server.Close)

			node := &Node{conf: &Configuration{BitcoinRPC: server.URL}}
			err := node.bitcoinBroadcastTransaction(expectedHash, raw, common.SafeChainBitcoin)
			if test.wantError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantError)
			}
		})
	}
}

func TestValidateObserverEthereumNativeSweep(t *testing.T) {
	const (
		safeAddress = "0x1111111111111111111111111111111111111111"
		receiver    = "0x2222222222222222222222222222222222222222"
		requestID   = "0ca34767-3a70-4a28-afd9-51c9bce4ecf5"
	)
	amount := big.NewInt(1_000_000_000_000_000_000)
	keeperStore, err := keeperstore.OpenSQLite3Store(t.TempDir() + "/keeper.sqlite3")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, keeperStore.Close()) })

	balance, err := keeperStore.ReadEthereumBalance(t.Context(), safeAddress, "native-asset", "safe-native-asset")
	require.NoError(t, err)
	balance.AssetAddress = ethereum.EthereumEmptyAddress
	balance.UpdateBalance(amount)
	balances := map[string]*keeperstore.SafeBalance{balance.AssetId: balance}

	safe := &keeperstore.Safe{
		Address: safeAddress,
		Chain:   common.SafeChainEthereum,
		Nonce:   42,
	}
	tx, err := ethereum.CreateTransaction(
		t.Context(),
		ethereum.TypeETHTx,
		ethereum.GetEvmChainID(int64(safe.Chain)),
		requestID,
		safeAddress,
		receiver,
		ethereum.EthereumEmptyAddress,
		amount.String(),
		big.NewInt(safe.Nonce),
	)
	require.NoError(t, err)

	outputs, err := validateObserverEthereumSweep(safe, tx, requestID, tx.RequestHash, receiver, balances)
	require.NoError(t, err)
	require.Len(t, outputs, 1)
	require.Equal(t, receiver, outputs[0].Destination)
	require.Equal(t, amount, outputs[0].Amount)

	_, err = validateObserverEthereumSweep(safe, tx, requestID+"-other", tx.RequestHash, receiver, balances)
	require.Error(t, err)
	_, err = validateObserverEthereumSweep(safe, tx, requestID, strings.Repeat("0", 64), receiver, balances)
	require.Error(t, err)
	_, err = validateObserverEthereumSweep(
		safe,
		tx,
		requestID,
		tx.RequestHash,
		"0x3333333333333333333333333333333333333333",
		balances,
	)
	require.Error(t, err)

	wrongSafe := *safe
	wrongSafe.Nonce++
	_, err = validateObserverEthereumSweep(&wrongSafe, tx, requestID, tx.RequestHash, receiver, balances)
	require.Error(t, err)
}

func TestObserverEthereumRecoveryBroadcastRevalidatesApprovedSweep(t *testing.T) {
	const (
		safeAddress = "0x1111111111111111111111111111111111111111"
		receiver    = "0x2222222222222222222222222222222222222222"
		holder      = "holder-key"
		requestID   = "0ca34767-3a70-4a28-afd9-51c9bce4ecf5"
	)
	const nonce = int64(42)
	amount := big.NewInt(1_000_000_000_000_000_000)
	approved, err := ethereum.CreateTransaction(
		t.Context(),
		ethereum.TypeETHTx,
		1,
		requestID,
		safeAddress,
		receiver,
		ethereum.EthereumEmptyAddress,
		amount.String(),
		big.NewInt(nonce),
	)
	require.NoError(t, err)

	keeperStore, err := keeperstore.OpenSQLite3Store(t.TempDir() + "/keeper.sqlite3")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, keeperStore.Close()) })
	now := time.Now().UTC()
	safe := &keeperstore.Safe{
		Holder:      holder,
		Chain:       common.SafeChainEthereum,
		Signer:      "signer-key",
		Observer:    "observer-key",
		Timelock:    24 * time.Hour,
		Address:     safeAddress,
		Extra:       []byte{0},
		Receivers:   []string{"receiver-id"},
		Threshold:   1,
		RequestId:   uuid.Must(uuid.NewV4()).String(),
		Nonce:       nonce,
		State:       common.RequestStatePending,
		SafeAssetId: "safe-native-asset",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	require.NoError(t, keeperStore.WriteUnfinishedSafe(t.Context(), safe))

	request := &common.Request{
		Id:        requestID,
		MixinHash: mixincrypto.Sha256Hash([]byte(requestID)),
		AssetId:   "native-asset",
		Amount:    decimal.NewFromInt(1),
		Role:      common.RequestRoleHolder,
		Action:    common.ActionEthereumSafeCloseAccount,
		Curve:     common.CurveSecp256k1ECDSAEthereum,
		Holder:    holder,
		State:     common.RequestStateInitial,
		CreatedAt: now,
		Output: &mtg.Action{UnifiedOutput: mtg.UnifiedOutput{
			OutputId: uuid.Must(uuid.NewV4()).String(),
		}},
	}
	require.NoError(t, keeperStore.WriteRequestIfNotExist(t.Context(), request))
	keeperTransaction := &keeperstore.Transaction{
		TransactionHash: approved.RequestHash,
		RawTransaction:  hex.EncodeToString(approved.Marshal()),
		Holder:          holder,
		Chain:           common.SafeChainEthereum,
		AssetId:         "native-asset",
		State:           common.RequestStatePending,
		RequestId:       requestID,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	require.NoError(t, keeperStore.WriteTransactionWithRequest(
		t.Context(),
		keeperTransaction,
		nil,
		nil,
		nil,
		request,
	))

	var liveNonce atomic.Int64
	liveNonce.Store(nonce)
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request observerRPCTestRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		var result any
		switch request.Method {
		case "eth_chainId":
			result = "0x1"
		case "eth_blockNumber":
			result = "0x64"
		case "eth_call":
			result = "0x" + fmt.Sprintf("%064x", liveNonce.Load())
		default:
			t.Errorf("unexpected method %q", request.Method)
			result = nil
		}
		_ = json.NewEncoder(w).Encode(observerRPCTestResponse{
			JSONRPC: "2.0",
			Result:  result,
			ID:      request.ID,
		})
	}))
	t.Cleanup(rpc.Close)

	node := &Node{
		conf:        &Configuration{EthereumRPC: rpc.URL},
		keeperStore: keeperStore,
	}
	transaction := &Transaction{
		TransactionHash: approved.RequestHash,
		Chain:           common.SafeChainEthereum,
		Holder:          holder,
	}
	recovery := &Recovery{}

	require.NoError(t, node.validateEthereumRecoveryBroadcast(
		t.Context(), rpc.URL, transaction, recovery, approved,
	))
	liveNonce.Store(nonce + 1)
	require.NoError(t, node.validateEthereumRecoveryBroadcast(
		t.Context(), rpc.URL, transaction, recovery, approved,
	))

	liveNonce.Store(nonce + 2)
	err = node.validateEthereumRecoveryBroadcast(t.Context(), rpc.URL, transaction, recovery, approved)
	require.ErrorContains(t, err, "invalid live sweep nonce")

	liveNonce.Store(nonce)
	mutated, err := ethereum.CreateTransaction(
		t.Context(),
		ethereum.TypeETHTx,
		1,
		requestID,
		safeAddress,
		"0x3333333333333333333333333333333333333333",
		ethereum.EthereumEmptyAddress,
		amount.String(),
		big.NewInt(nonce),
	)
	require.NoError(t, err)
	err = node.validateEthereumRecoveryBroadcast(t.Context(), rpc.URL, transaction, recovery, mutated)
	require.ErrorContains(t, err, "invalid broadcast sweep")
}
