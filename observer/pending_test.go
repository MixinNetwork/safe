package observer

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	ga "github.com/ethereum/go-ethereum/accounts/abi"
	ec "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestPendingDepositConfirmationAndHTTP(t *testing.T) {
	f := newTransactionHTTPFixture(t)
	ctx := t.Context()
	now := time.Now().UTC().Add(-time.Minute)
	safe, err := f.node.keeperStore.ReadSafeByAddress(ctx, f.address)
	require.NoError(t, err)
	d := &PendingDeposit{TransactionHash: "pending-hash", OutputIndex: 3, AssetId: common.SafeEthereumChainId,
		AssetAddress: ethereum.EthereumEmptyAddress, Amount: "1.25", Receiver: f.address,
		Sender: "sender-address", State: common.RequestStateInitial, Chain: common.SafeChainEthereum, Holder: safe.Holder, CreatedAt: now}
	require.NoError(t, f.node.store.WritePendingDepositRecord(ctx, d))
	duplicate := *d
	duplicate.CreatedAt = time.Now().UTC()
	require.NoError(t, f.node.store.WritePendingDepositRecord(ctx, &duplicate))
	otherChain := *d
	otherChain.Chain = common.SafeChainPolygon
	require.NoError(t, f.node.store.WritePendingDepositRecord(ctx, &otherChain))
	deposit := &Deposit{TransactionHash: d.TransactionHash, OutputIndex: d.OutputIndex, AssetId: d.AssetId,
		Amount: d.Amount, Receiver: d.Receiver, Chain: d.Chain, State: common.RequestStateInitial,
		RequestId: "deposit-request", CreatedAt: now, UpdatedAt: now}
	deposit.Holder = safe.Holder
	require.NoError(t, f.node.store.WritePendingDepositIfNotExists(ctx, deposit))
	get := func(target string, pending bool) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if pending {
			f.node.httpListPendingDeposits(w, r, nil)
		} else {
			f.node.httpListDeposits(w, r, nil)
		}
		return w
	}
	chain := fmt.Sprint(d.Chain)
	response := get("/pending_deposits?chain="+chain+"&holder="+safe.Holder, true)
	require.Equal(t, http.StatusOK, response.Code)
	var pending []*PendingDeposit
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &pending))
	require.Len(t, pending, 1)
	require.True(t, pending[0].CreatedAt.Equal(now), "duplicate scan preserves creation time")
	require.Equal(t, d.Amount, pending[0].Amount)
	require.Equal(t, d.AssetAddress, pending[0].AssetAddress)
	require.Equal(t, d.Sender, pending[0].Sender)
	require.Equal(t, d.Holder, pending[0].Holder)
	require.Equal(t, common.RequestStateInitial, pending[0].State)
	var fields []map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &fields))
	require.Equal(t, d.AssetAddress, fields[0]["asset_address"])
	require.Equal(t, d.Sender, fields[0]["sender"])
	require.Equal(t, d.Holder, fields[0]["holder"])
	for _, query := range []string{"&holder=unknown",
		fmt.Sprintf("&offset=%d", now.Add(time.Second).UnixNano())} {
		require.JSONEq(t, `[]`, get("/pending_deposits?chain="+chain+query, true).Body.String())
	}
	for _, query := range []string{"", "?chain=999", "?chain=invalid"} {
		require.Equal(t, http.StatusBadRequest, get("/pending_deposits"+query, true).Code)
	}
	require.JSONEq(t, `[]`, get("/deposits?chain="+chain, false).Body.String())
	require.NoError(t, f.node.store.ConfirmPendingDeposit(ctx, d.TransactionHash, d.OutputIndex, deposit.RequestId, d.Chain))
	// A slow or restarted scanner must not recreate a confirmed observation.
	require.NoError(t, f.node.store.WritePendingDepositRecord(ctx, d))
	require.JSONEq(t, `[]`, get("/pending_deposits?chain="+chain, true).Body.String())
	var retained int
	require.NoError(t, f.node.store.db.QueryRow("SELECT COUNT(*) FROM pending_deposits WHERE chain=?", d.Chain).Scan(&retained))
	require.Equal(t, 1, retained, "confirmed pending observations remain stored as history")
	var state int
	require.NoError(t, f.node.store.db.QueryRowContext(ctx, "SELECT state FROM pending_deposits WHERE chain=?", d.Chain).Scan(&state))
	require.Equal(t, common.RequestStateDone, state)
	_, err = f.node.store.db.ExecContext(ctx, "DELETE FROM pending_deposits WHERE chain=?", d.Chain)
	require.NoError(t, err)
	require.NoError(t, f.node.store.WritePendingDepositRecord(ctx, d))
	require.NoError(t, f.node.store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_deposits WHERE chain=?", d.Chain).Scan(&retained))
	require.Zero(t, retained, "a late scan must not insert an already confirmed deposit")
	response = get("/deposits?chain="+chain, false)
	require.Equal(t, http.StatusOK, response.Code)
	var confirmed []map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &confirmed))
	require.Len(t, confirmed, 1)
	require.Equal(t, "done", confirmed[0]["state"])
	remaining, err := f.node.store.ListPendingDeposits(ctx, int(otherChain.Chain), "", 0)
	require.NoError(t, err)
	require.Len(t, remaining, 1, "confirmation does not delete an observation on another chain")
	require.Equal(t, common.RequestStateInitial, remaining[0].State)
}

func TestBitcoinPendingMempoolExcludesChange(t *testing.T) {
	for _, chain := range []byte{common.SafeChainBitcoin, common.SafeChainLitecoin} {
		t.Run(fmt.Sprint(chain), func(t *testing.T) {
			f := newTransactionHTTPFixture(t)
			_, err := f.keeperDB.Exec("UPDATE safes SET chain=?", chain)
			require.NoError(t, err)
			_, err = f.keeperDB.Exec(`UPDATE transactions SET data='[{"receiver":"recipient","amount":"1"}]'`)
			require.NoError(t, err)
			_, err = f.node.store.db.Exec("UPDATE transactions SET spent_hash=?", "mempool-hash")
			require.NoError(t, err)
			rawCalls := 0
			senderCalls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var q struct {
					Method string
					Params []json.RawMessage
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&q))
				var result any
				switch q.Method {
				case "getrawmempool":
					result = []string{"mempool-hash"}
				case "getrawtransaction":
					if string(q.Params[0]) == `"previous-hash"` {
						senderCalls++
						result = map[string]any{"txid": "previous-hash", "vout": []any{
							map[string]any{"n": 0, "value": 5, "scriptPubKey": map[string]any{"type": "witness_v0_keyhash", "address": "sender-address"}},
						}}
						break
					}
					rawCalls++
					result = map[string]any{"txid": "mempool-hash", "vin": []any{map[string]any{"txid": "previous-hash", "vout": 0}}, "vout": []any{
						map[string]any{"n": 0, "value": 1.25, "scriptPubKey": map[string]any{"type": "witness_v0_scripthash", "address": f.address}},
						map[string]any{"n": 1, "value": 2, "scriptPubKey": map[string]any{"type": "witness_v0_scripthash", "address": f.address}},
						map[string]any{"n": 2, "value": 3, "scriptPubKey": map[string]any{"type": "witness_v0_scripthash", "address": "unknown"}},
					}}
				default:
					t.Errorf("unexpected RPC %s", q.Method)
				}
				require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"result": result, "error": nil}))
			}))
			defer server.Close()
			f.node.conf = &Configuration{
				BitcoinRPC: server.URL, LitecoinRPC: server.URL,
				Bitcoin: ChainParams{TransactionMinimum: "1.25"}, Litecoin: ChainParams{TransactionMinimum: "1.25"},
			}
			seen := make(map[string]bool)
			require.NoError(t, f.node.scanBitcoinPendingDeposits(t.Context(), chain, seen))
			require.NoError(t, f.node.scanBitcoinPendingDeposits(t.Context(), chain, seen))
			require.Equal(t, 1, rawCalls, "unchanged mempool entries do not refetch transactions")
			require.Equal(t, 1, senderCalls, "sender is resolved only for newly observed deposits")
			pending, err := f.node.store.ListPendingDeposits(t.Context(), int(chain), "", 0)
			require.NoError(t, err)
			require.Len(t, pending, 1)
			require.Equal(t, int64(0), pending[0].OutputIndex)
			require.Equal(t, "1.25", pending[0].Amount)
			require.Empty(t, pending[0].AssetAddress, "Bitcoin native deposits have no token contract address")
			require.Equal(t, "sender-address", pending[0].Sender)
			safe, err := f.node.keeperStore.ReadSafeByAddress(t.Context(), f.address)
			require.NoError(t, err)
			require.Equal(t, safe.Holder, pending[0].Holder)
			deposits, err := f.node.store.ListDeposits(t.Context(), int(chain), "", 0, 0)
			require.NoError(t, err)
			require.Empty(t, deposits, "mempool scanning does not enter the confirmation queue")
		})
	}
}

func TestBitcoinPendingUsesDepositAdmissionChecks(t *testing.T) {
	for _, test := range []struct {
		name     string
		amount   float64
		credited bool
		outputs  int
	}{
		{name: "below minimum", amount: 0.00009999},
		{name: "already credited by keeper", amount: 1, credited: true},
		{name: "safe reached output limit", amount: 1, outputs: bitcoin.MaxUnspentUtxo / 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newTransactionHTTPFixture(t)
			ctx := t.Context()
			chain := byte(common.SafeChainBitcoin)
			_, err := f.keeperDB.ExecContext(ctx, "UPDATE safes SET chain=?", chain)
			require.NoError(t, err)
			f.node.conf = &Configuration{Bitcoin: ChainParams{TransactionMinimum: "0.0001"}}
			tx := &bitcoin.RPCTransaction{}
			require.NoError(t, json.Unmarshal([]byte(`{"txid":"pending-hash","vin":[{"txid":"previous-hash","vout":0}]}`), tx))
			now := time.Now().UTC()
			if test.credited {
				_, err := f.keeperDB.ExecContext(ctx, `INSERT INTO bitcoin_outputs
					(transaction_hash, output_index, address, satoshi, script, sequence, chain, state, request_id, created_at, updated_at)
					VALUES (?, 0, ?, 100000000, '', 0, ?, ?, 'credited-request', ?, ?)`,
					tx.TxId, f.address, chain, common.RequestStateInitial, now, now)
				require.NoError(t, err)
			}
			if test.outputs > 0 {
				_, err := f.keeperDB.ExecContext(ctx, `WITH RECURSIVE outputs(n) AS
					(VALUES(0) UNION ALL SELECT n+1 FROM outputs WHERE n+1<?)
					INSERT INTO bitcoin_outputs
					(transaction_hash, output_index, address, satoshi, script, sequence, chain, state, request_id, created_at, updated_at)
					SELECT 'output-'||n, 0, ?, 100000, '', 0, ?, ?, 'request-'||n, ?, ? FROM outputs`,
					test.outputs, f.address, chain, common.RequestStateInitial, now, now)
				require.NoError(t, err)
			}
			require.NoError(t, f.node.bitcoinRecordPendingDeposit(ctx, f.address, tx, 0, test.amount, chain))
			require.NoError(t, f.node.bitcoinWritePendingDeposit(ctx, f.address, tx, 0, test.amount, chain))
			pending, err := f.node.store.ListPendingDeposits(ctx, int(chain), "", 0)
			require.NoError(t, err)
			require.Empty(t, pending)
			deposits, err := f.node.store.ListDeposits(ctx, int(chain), "", 0, 0)
			require.NoError(t, err)
			require.Empty(t, deposits)
		})
	}
}

func TestEthereumPendingUsesDepositAdmissionChecks(t *testing.T) {
	for _, test := range []struct {
		name     string
		amount   string
		price    string
		icon     string
		credited bool
		assets   int
		want     int
	}{
		{name: "eligible deposit", amount: "0.1", price: "1", icon: "icon", want: 1},
		{name: "below minimum", amount: "0.00009999", price: "10000", icon: "icon"},
		{name: "below USD minimum", amount: "1", price: "0.01", icon: "icon"},
		{name: "invalid asset price", amount: "1", price: "invalid", icon: "icon"},
		{name: "default asset icon", amount: "1", price: "1", icon: DefaultIconUrl},
		{name: "already credited by keeper", amount: "1", price: "1", icon: "icon", credited: true},
		{name: "safe reached asset limit", amount: "1", price: "1", icon: "icon", assets: ethereum.MaxAssetsCount / 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newTransactionHTTPFixture(t)
			ctx := t.Context()
			chain := byte(common.SafeChainEthereum)
			transfer := &ethereum.Transfer{Hash: "pending-hash", AssetId: common.SafeEthereumChainId,
				TokenAddress: ethereum.EthereumEmptyAddress, Receiver: f.address,
				Value: ethereum.ParseAmount(test.amount, ethereum.ValuePrecision)}
			now := time.Now().UTC()
			if test.credited {
				safe, err := f.node.keeperStore.ReadSafeByAddress(ctx, f.address)
				require.NoError(t, err)
				_, err = f.keeperDB.ExecContext(ctx, `INSERT INTO deposits
					(transaction_hash, output_index, asset_id, amount, receiver, sender, state, chain, holder, category, created_at, updated_at)
					VALUES (?, 0, ?, ?, ?, '', ?, ?, ?, ?, ?, ?)`, transfer.Hash, transfer.AssetId, test.amount,
					f.address, common.RequestStateDone, chain, safe.Holder, common.ActionObserverHolderDeposit, now, now)
				require.NoError(t, err)
			}
			if test.assets > 0 {
				_, err := f.keeperDB.ExecContext(ctx, `WITH RECURSIVE assets(n) AS
					(VALUES(0) UNION ALL SELECT n+1 FROM assets WHERE n+1<?)
					INSERT INTO ethereum_balances (address, asset_id, asset_address, safe_asset_id, balance, latest_tx_hash, updated_at)
					SELECT ?, 'asset-'||n, 'token-'||n, 'safe-asset-'||n, '1', '', ? FROM assets`, test.assets, f.address, now)
				require.NoError(t, err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodGet, r.Method, "pending recording only fetches asset metadata")
				require.Equal(t, "/network/assets/"+transfer.AssetId, r.URL.Path)
				require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"data": &MixinNetworkAsset{
					AssetId: transfer.AssetId, ChainId: common.SafeEthereumChainId, PriceUSD: test.price, IconURL: test.icon,
				}}))
			}))
			defer server.Close()
			f.node.conf = &Configuration{MixinMessengerAPI: server.URL, Ethereum: ChainParams{TransactionMinimum: "0.0001"}}
			require.NoError(t, f.node.ethereumRecordPendingTransfer(ctx, transfer, chain))
			if test.want == 0 {
				require.NoError(t, f.node.ethereumWritePendingDeposit(ctx, transfer, chain))
			}
			pending, err := f.node.store.ListPendingDeposits(ctx, int(chain), "", 0)
			require.NoError(t, err)
			require.Len(t, pending, test.want)
			deposits, err := f.node.store.ListDeposits(ctx, int(chain), "", 0, 0)
			require.NoError(t, err)
			require.Empty(t, deposits, "pending observations do not enter the keeper confirmation queue")
		})
	}
}

func TestEthereumPendingScansLatestBlockAndRetries(t *testing.T) {
	for _, chain := range []byte{common.SafeChainEthereum, common.SafeChainPolygon} {
		t.Run(fmt.Sprint(chain), func(t *testing.T) {
			f := newTransactionHTTPFixture(t)
			_, err := f.keeperDB.Exec("UPDATE safes SET chain=?", chain)
			require.NoError(t, err)
			ctx := t.Context()
			height := depositCheckpointDefault(chain) + 1
			hash := "0x" + strings.Repeat("a", 64)
			blockHash := ec.HexToHash("0x" + strings.Repeat("b", 64))
			token := "0x3333333333333333333333333333333333333333"
			assetId := ethereum.GenerateAssetId(chain, token)
			decimalCalls := 0
			stringType, err := ga.NewType("string", "", nil)
			require.NoError(t, err)
			metadata, err := (ga.Arguments{{Type: stringType}}).Pack("Token")
			require.NoError(t, err)
			log := types.Log{Address: ec.HexToAddress(token), Topics: []ec.Hash{
				crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)")), ec.HexToHash("0x2"), ec.HexToHash(f.address),
			}, Data: ec.LeftPadBytes(big.NewInt(1234567890123456789).Bytes(), 32), BlockNumber: uint64(height),
				TxHash: ec.HexToHash(hash), BlockHash: blockHash, Index: 2}
			failLogs := true
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/network/assets/") {
					id := strings.TrimPrefix(r.URL.Path, "/network/assets/")
					_, chainId, _ := f.node.ethereumParams(chain)
					require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"data": &MixinNetworkAsset{
						AssetId: id, ChainId: chainId, IconURL: "https://example.com/token.png", PriceUSD: "100", Precision: 18,
					}}))
					return
				}
				var q struct {
					Method string
					ID     json.RawMessage
					Params []json.RawMessage
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&q))
				w.Header().Set("Content-Type", "application/json")
				if q.Method == "eth_getLogs" && failLogs {
					require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID,
						"error": map[string]any{"code": -32000, "message": "backend unavailable"}}))
					return
				}
				var result any
				switch q.Method {
				case "eth_blockNumber":
					result = fmt.Sprintf("0x%x", height)
				case "debug_traceBlockByNumber":
					require.JSONEq(t, fmt.Sprintf(`"0x%x"`, height), string(q.Params[0]))
					result = []*ethereum.RPCBlockCallTrace{{Result: &ethereum.RPCTransactionCallTrace{
						Type: "CALL", To: f.address, From: "0x2222222222222222222222222222222222222222", Value: "0xde0b6b3a7640000",
						Calls: []*ethereum.RPCTransactionCallTrace{{Type: "CALL", To: f.address, Value: "0x1", Error: "execution reverted"}},
					}}}
				case "eth_getBlockByNumber":
					result = map[string]any{"number": fmt.Sprintf("0x%x", height), "hash": blockHash.Hex(),
						"transactions": []any{map[string]any{"hash": hash}}}
				case "eth_getLogs":
					result = []types.Log{log}
				case "eth_call":
					var call struct{ Input, Data string }
					require.NoError(t, json.Unmarshal(q.Params[0], &call))
					if call.Input == "" {
						call.Input = call.Data
					}
					switch call.Input {
					case "0x313ce567":
						decimalCalls++
						result = fmt.Sprintf("0x%064x", 18)
					case "0x06fdde03", "0x95d89b41":
						result = fmt.Sprintf("0x%x", metadata)
					default:
						t.Errorf("unexpected token metadata call %s", call.Input)
					}
				default:
					t.Errorf("unexpected RPC %s", q.Method)
				}
				require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result}))
			}))
			defer server.Close()
			f.node.conf = &Configuration{
				EthereumRPC: server.URL, PolygonRPC: server.URL, MixinMessengerAPI: server.URL,
				Ethereum: ChainParams{TransactionMinimum: "0.0001"}, Polygon: ChainParams{TransactionMinimum: "0.0001"},
			}
			require.NoError(t, f.node.store.WriteProperty(ctx, depositCheckpointKey(chain), fmt.Sprint(height-1)))
			require.NoError(t, f.node.store.migratePendingDepositCheckpoints(ctx))
			err = f.node.scanEthereumPendingDeposits(ctx, chain)
			require.Error(t, err)
			checkpoint, err := f.node.readPendingDepositCheckpoint(ctx, chain)
			require.NoError(t, err)
			require.Equal(t, height-1, checkpoint, "failed blocks do not advance the cursor")
			failLogs = false
			err = f.node.scanEthereumPendingDeposits(ctx, chain)
			require.NoError(t, err)
			pending, err := f.node.store.ListPendingDeposits(ctx, int(chain), "", 0)
			require.NoError(t, err)
			require.Len(t, pending, 2, "latest block is scanned without waiting for finalization")
			require.Equal(t, "1", pending[0].Amount)
			require.Equal(t, ethereum.EthereumEmptyAddress, pending[0].AssetAddress)
			require.Equal(t, "0x2222222222222222222222222222222222222222", pending[0].Sender)
			require.Equal(t, int64(math.MaxInt32+2), pending[1].OutputIndex)
			require.Equal(t, "1.23456789", pending[1].Amount, "pending amounts follow the existing eight-decimal rounding")
			require.Equal(t, assetId, pending[1].AssetId)
			require.Equal(t, token, pending[1].AssetAddress)
			require.Equal(t, ec.HexToAddress("0x2").Hex(), pending[1].Sender)
			safe, err := f.node.keeperStore.ReadSafeByAddress(ctx, f.address)
			require.NoError(t, err)
			require.Equal(t, safe.Holder, pending[0].Holder)
			require.Equal(t, safe.Holder, pending[1].Holder)
			require.NoError(t, f.node.ethereumRecordPendingBlock(ctx, height, chain))
			require.Equal(t, 2, decimalCalls, "pending scans use the existing FetchAsset metadata flow")
			checkpoint, err = f.node.readPendingDepositCheckpoint(ctx, chain)
			require.NoError(t, err)
			require.Equal(t, height, checkpoint)
			formal, err := f.node.readDepositCheckpoint(ctx, chain)
			require.NoError(t, err)
			require.Equal(t, height-1, formal, "fast scanning leaves the confirmed cursor untouched")
			deposits, err := f.node.store.ListDeposits(ctx, int(chain), "", 0, 0)
			require.NoError(t, err)
			require.Empty(t, deposits)
		})
	}
}
