package keeper

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestVerifyPolygonDepositRequiresFinalization(t *testing.T) {
	const receiver = "0x2222222222222222222222222222222222222222"
	const blockHeight = uint64(1000)
	hash := "0x" + strings.Repeat("a", 64)
	amount := big.NewInt(100_000_000_000_000)
	value := fmt.Sprintf("0x%x", amount)

	for _, sender := range []struct {
		name    string
		address string
		safe    bool
	}{
		{name: "external", address: "0x1111111111111111111111111111111111111111"},
		{name: "formerly trusted", address: "0x1616b057F8a89955d4A4f9fd9Eb10289ac0e44A1"},
		{name: "safe", address: "0x3333333333333333333333333333333333333333", safe: true},
	} {
		t.Run(sender.name, func(t *testing.T) {
			node, closeNode := coverageKeeperNode(t)
			t.Cleanup(closeNode)
			if sender.safe {
				require.NoError(t, node.store.WriteUnfinishedSafe(t.Context(), &store.Safe{
					Holder: coverageKeeperPublicKey, Address: sender.address,
					Chain: common.SafeChainPolygon, State: common.RequestStatePending,
					RequestId: uuid.Must(uuid.NewV4()).String(), Extra: []byte{},
				}))
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
					ID     json.RawMessage   `json:"id"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Errorf("decode RPC request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				var result any
				switch request.Method {
				case "eth_getTransactionByHash":
					result = map[string]any{
						"hash": hash, "blockNumber": fmt.Sprintf("0x%x", blockHeight),
						"from": sender.address, "to": receiver, "value": value,
					}
				case "debug_traceTransaction":
					result = map[string]any{
						"type": "CALL", "from": sender.address, "to": receiver, "value": value,
					}
				case "eth_getLogs":
					result = []any{}
				case "eth_getBalance":
					if len(request.Params) != 2 {
						t.Errorf("unexpected balance params: %s", request.Params)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					var height string
					if err := json.Unmarshal(request.Params[1], &height); err != nil {
						t.Errorf("decode balance height: %v", err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					switch height {
					case fmt.Sprintf("0x%x", blockHeight-1):
						result = "0x0"
					case fmt.Sprintf("0x%x", blockHeight):
						result = value
					default:
						t.Errorf("unexpected balance height: %s", height)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
				default:
					t.Errorf("unexpected RPC method: %s", request.Method)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": request.ID, "result": result,
				}); err != nil {
					t.Errorf("encode RPC response: %v", err)
				}
			}))
			t.Cleanup(server.Close)
			node.conf.PolygonRPC = server.URL

			for _, confirmations := range []uint64{0, 1, 255, 256} {
				t.Run(fmt.Sprintf("%d confirmations", confirmations), func(t *testing.T) {
					createdAt := time.Unix(1_700_000_000+int64(confirmations), 0).UTC()
					id := uuid.Must(uuid.NewV4()).String()
					req := &common.Request{
						Id: id, MixinHash: crypto.Sha256Hash([]byte(id)), CreatedAt: createdAt,
						State: common.RequestStateInitial, Role: common.RequestRoleObserver,
						Output: &mtg.Action{UnifiedOutput: mtg.UnifiedOutput{OutputId: uuid.Must(uuid.NewV4()).String()}},
					}
					require.NoError(t, node.store.WriteRequestIfNotExist(t.Context(), req))
					require.NoError(t, node.store.WriteNetworkInfoFromRequest(t.Context(), &store.NetworkInfo{
						RequestId: id, Chain: common.SafeChainPolygon, CreatedAt: createdAt,
						Height: blockHeight + confirmations - 1, Hash: "0x" + strings.Repeat("b", 64),
					}, req))

					transfer, err := node.verifyEthereumTransaction(t.Context(), req, &Deposit{
						Chain: common.SafeChainPolygon, Asset: common.SafePolygonChainId,
						Hash: hash, AssetAddress: ethereum.EthereumEmptyAddress, Amount: amount,
					}, &store.Safe{Chain: common.SafeChainPolygon, Address: receiver}, &store.Asset{Decimals: 18})
					if confirmations < 256 {
						require.ErrorContains(t, err, "ethereum.CheckFinalization")
						require.Nil(t, transfer)
						return
					}
					require.NoError(t, err)
					require.NotNil(t, transfer)
					require.Equal(t, receiver, transfer.Receiver)
					require.Equal(t, sender.address, transfer.Sender)
					require.Zero(t, amount.Cmp(transfer.Value))
				})
			}
		})
	}
}
