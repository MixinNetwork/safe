package observer

import (
	"context"
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

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestIsTxStuckRequiresFreshRPCTipAndMatchingNonce(t *testing.T) {
	var stamp, nonce atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Error(err)
			return
		}
		var result any
		switch q.Method {
		case "eth_blockNumber":
			result = "0x64"
		case "eth_chainId":
			result = "0x1"
		case "eth_getBlockByNumber":
			result = map[string]any{"hash": "0x" + strings.Repeat("0", 64), "number": "0x64",
				"timestamp": fmt.Sprintf("0x%x", stamp.Load()), "transactions": []string{}}
		case "eth_call":
			result = fmt.Sprintf("0x%064x", nonce.Load())
		default:
			t.Errorf("unexpected RPC method %s", q.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}))
	t.Cleanup(server.Close)
	node := &Node{conf: &Configuration{EthereumRPC: server.URL}}
	st, err := ethereum.CreateTransaction(t.Context(), ethereum.TypeETHTx, 1, uuid.Must(uuid.NewV4()).String(),
		"0x0000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000002",
		ethereum.EthereumEmptyAddress, "1", big.NewInt(0))
	require.NoError(t, err)
	tx := &Transaction{Chain: common.SafeChainEthereum, State: common.RequestStateDone,
		UpdatedAt: time.Now().Add(-48 * time.Hour), RawTransaction: hex.EncodeToString(st.Marshal())}
	for _, tc := range []struct {
		name  string
		age   time.Duration
		nonce int64
		want  bool
	}{
		{"fresh unchanged nonce", 5 * time.Second, 0, true},
		{"stale unchanged nonce", 24 * time.Hour, 0, false},
		{"future tip", -24 * time.Hour, 0, false},
		{"fresh advanced nonce", 10 * time.Second, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stamp.Store(time.Now().Add(-tc.age).Unix())
			nonce.Store(tc.nonce)
			require.Equal(t, tc.want, node.isTxStuck(t.Context(), tx))
		})
	}
}

func TestEthereumSpendLoopHandlesBalanceRPCError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := coverageObserverStore(t)
	requested := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Error(err)
			return
		}
		if q.Method != "eth_getBalance" {
			t.Errorf("unexpected RPC method %s", q.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID,
			"error": map[string]any{"code": -32000, "message": "temporary backend failure"}})
		requested <- struct{}{}
	}))
	t.Cleanup(server.Close)
	require.NoError(t, s.WriteAssetMeta(ctx, &Asset{AssetId: common.SafeEthereumChainId,
		MixinId: crypto.Sha256Hash([]byte(common.SafeEthereumChainId)).String(), Decimals: 18,
		Chain: common.SafeChainEthereum, CreatedAt: time.Now()}))
	require.NoError(t, s.WriteTransactionApprovalIfNotExists(ctx,
		coverageObserverTransaction("balance-error", common.RequestStateDone, common.SafeChainEthereum, time.Now())))
	node := &Node{store: s, conf: &Configuration{EthereumRPC: server.URL, EVMKey: strings.Repeat("0", 63) + "1"}}
	finished := make(chan any, 1)
	go func() {
		defer func() { finished <- recover() }()
		node.ethereumTransactionSpendLoop(ctx, common.SafeChainEthereum)
	}()
	select {
	case <-requested:
	case p := <-finished:
		t.Fatalf("spend loop stopped before requesting balance: %v", p)
	case <-time.After(10 * time.Second):
		t.Fatal("balance was not requested")
	}
	cancel()
	select {
	case p := <-finished:
		require.Nil(t, p, "an RPC error must not dereference a nil balance")
	case <-time.After(10 * time.Second):
		t.Fatal("spend loop did not stop after cancellation")
	}
}

func TestNewBitcoinFeeOutputPreservesAddressAndChain(t *testing.T) {
	ctx := t.Context()
	s := coverageObserverStore(t)
	private, public := btcec.PrivKeyFromBytes([]byte{17})
	addr, err := address.NewAddressWitnessPubKeyHash(address.Hash160(public.SerializeCompressed()), bitcoin.NetConfig(common.SafeChainBitcoin))
	require.NoError(t, err)
	receiver := addr.EncodeAddress()
	require.NoError(t, s.WriteAccountantKeys(ctx, common.CurveSecp256k1ECDSABitcoin, map[string]*btcec.PrivateKey{receiver: private}))
	script, err := bitcoin.ParseAddress(receiver, common.SafeChainBitcoin)
	require.NoError(t, err)
	prev := wire.NewMsgTx(2)
	prev.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, 0), nil, nil))
	prev.AddTxOut(wire.NewTxOut(100000, script))
	raw, err := bitcoin.MarshalWiredTransaction(prev, wire.WitnessEncoding, common.SafeChainBitcoin)
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, s.WriteBitcoinUTXOIfNotExists(ctx, &Output{TransactionHash: prev.TxHash().String(),
		Address: receiver, Satoshi: 100000, Chain: common.SafeChainBitcoin,
		State: common.RequestStateInitial, CreatedAt: now, UpdatedAt: now}))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Error(err)
			return
		}
		if q.Method != "getrawtransaction" {
			t.Errorf("unexpected method: %s", q.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": q.ID, "result": map[string]any{
			"txid": prev.TxHash().String(), "hex": hex.EncodeToString(raw),
			"vout": []any{map[string]any{"value": 0.001, "n": 0,
				"scriptPubKey": map[string]any{"type": "witness_v0_keyhash", "address": receiver}}}}})
	}))
	t.Cleanup(server.Close)
	node := &Node{store: s, conf: &Configuration{BitcoinRPC: server.URL}}
	tx := coverageObserverTransaction("new-fee", common.RequestStateDone, common.SafeChainBitcoin, now)
	var feeHash string
	for attempt := range 2 {
		out, err := node.bitcoinRetrieveFeeInputsForTransaction(ctx, 10000, 1, tx)
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Equal(t, receiver, out.Address)
		require.Equal(t, byte(common.SafeChainBitcoin), out.Chain)
		key, err := s.ReadAccountantPrivateKey(ctx, out.Address)
		require.NoError(t, err)
		require.Equal(t, hex.EncodeToString(private.Serialize()), key)
		if attempt == 0 {
			feeHash = out.TransactionHash
		} else {
			require.Equal(t, feeHash, out.TransactionHash)
		}
	}
}
