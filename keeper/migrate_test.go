package keeper

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestSafeTokenMigrationValidation(t *testing.T) {
	for _, test := range []struct {
		name          string
		chain         byte
		missingSafe   bool
		pendingSafe   bool
		nonPolygon    bool
		undeployed    bool
		invalidExtra  bool
		wrongReceiver bool
		foreignAsset  bool
		tokenBalance  bool
	}{
		{name: "bitcoin", chain: common.SafeChainBitcoin},
		{name: "litecoin", chain: common.SafeChainLitecoin},
		{name: "ethereum native asset", chain: common.SafeChainEthereum},
		{name: "polygon token", chain: common.SafeChainPolygon, tokenBalance: true},
		{name: "non Polygon bond asset", nonPolygon: true},
		{name: "undeployed bond asset", undeployed: true},
		{name: "missing receiver", invalidExtra: true},
		{name: "wrong receiver", wrongReceiver: true},
		{name: "missing safe", missingSafe: true},
		{name: "pending safe", pendingSafe: true},
		{name: "foreign bitcoin asset", chain: common.SafeChainBitcoin, foreignAsset: true},
		{name: "foreign ethereum asset", chain: common.SafeChainEthereum, foreignAsset: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			node, closeNode := coverageKeeperNode(t)
			t.Cleanup(closeNode)
			ctx := t.Context()
			underlying := uuid.Must(uuid.NewV4())
			assetID := uuid.Must(uuid.NewV4()).String()
			assetKey := "0x1111111111111111111111111111111111111111"
			assetChain := byte(common.SafeChainPolygon)
			if test.nonPolygon {
				assetChain = common.SafeChainEthereum
			}
			for _, asset := range []*store.Asset{
				{AssetId: assetID, AssetKey: assetKey, Chain: assetChain},
				{AssetId: underlying.String(), Chain: common.SafeChainEthereum},
			} {
				asset.MixinId = crypto.Sha256Hash([]byte(asset.AssetId)).String()
				require.NoError(t, node.store.WriteAssetMeta(ctx, asset))
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var call struct {
					ID     json.RawMessage   `json:"id"`
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
					t.Errorf("decode factory call: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if test.nonPolygon {
					t.Error("non Polygon asset must be rejected before calling the factory")
				}
				if !assertFactoryCall(t, call.Method, call.Params, node.conf.PolygonFactoryAddress, assetKey) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				deployed := new(big.Int).SetBytes(underlying.Bytes())
				if test.undeployed {
					deployed.SetInt64(0)
				}
				if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": fmt.Sprintf("0x%064x", deployed)}); err != nil {
					t.Errorf("encode factory response: %v", err)
				}
			}))
			t.Cleanup(server.Close)
			node.conf.PolygonRPC = server.URL
			extra := common.DecodeHexOrPanic(node.conf.PolygonObserverDepositEntry[2:])
			if test.invalidExtra {
				extra = extra[:19]
			} else if test.wrongReceiver {
				extra = make([]byte, 20)
			}
			out := coverageKeeperOutput(node, uuid.Must(uuid.NewV4()).String(), common.ActionMigrateSafeToken, common.CurveSecp256k1ECDSABitcoin, extra, "holder")
			out.AssetId = assetID
			req, err := node.parseRequest(out)
			require.NoError(t, err)
			require.NoError(t, node.store.WriteRequestIfNotExist(ctx, req))
			chain := test.chain
			if chain == 0 {
				chain = common.SafeChainBitcoin
			}
			safe := &store.Safe{
				Holder: req.Holder, Address: "safe-address", Chain: chain, SafeAssetId: assetID,
				RequestId: req.Id, State: common.RequestStateDone, Extra: []byte{},
				Receivers: []string{"receiver"}, Threshold: 1,
				CreatedAt: req.CreatedAt, UpdatedAt: req.CreatedAt,
			}
			if test.foreignAsset || test.tokenBalance {
				safe.SafeAssetId = uuid.Must(uuid.NewV4()).String()
			}
			if test.pendingSafe {
				safe.State = common.RequestStatePending
				require.NoError(t, node.store.WriteUnfinishedSafe(ctx, safe))
			} else if !test.missingSafe {
				// Account creation has its own request; the migration must remain initial.
				setup := *req
				setup.Id = uuid.Must(uuid.NewV4()).String()
				setup.MixinHash = crypto.Sha256Hash([]byte(setup.Id))
				setupOutput := *out
				setupOutput.OutputId = uuid.Must(uuid.NewV4()).String()
				setup.Output = &setupOutput
				require.NoError(t, node.store.WriteRequestIfNotExist(ctx, &setup))
				safe.RequestId = setup.Id
				require.NoError(t, node.store.WriteSafeWithRequest(ctx, safe, nil, &setup))
			}
			if test.tokenBalance {
				balance, err := node.store.ReadEthereumBalance(ctx, safe.Address, underlying.String(), assetID)
				require.NoError(t, err)
				balance.UpdateBalance(big.NewInt(10))
				deposit := *req
				deposit.Id = uuid.Must(uuid.NewV4()).String()
				deposit.MixinHash = crypto.Sha256Hash([]byte(deposit.Id))
				depositOutput := *out
				depositOutput.OutputId = uuid.Must(uuid.NewV4()).String()
				deposit.Output = &depositOutput
				require.NoError(t, node.store.WriteRequestIfNotExist(ctx, &deposit))
				require.NoError(t, node.store.CreateEthereumBalanceDepositFromRequest(ctx, safe, balance, "deposit", 0, big.NewInt(10), "sender", &deposit, nil))
			}

			if test.foreignAsset || test.wrongReceiver {
				require.Panics(t, func() { node.checkSafeTokenMigration(ctx, req) })
				stored, err := node.store.ReadRequest(ctx, req.Id)
				require.NoError(t, err)
				require.Equal(t, uint8(common.RequestStateInitial), stored.State)
				result, handled, err := node.store.ReadActionResult(ctx, out.OutputId, req.Id)
				require.NoError(t, err)
				require.False(t, handled)
				require.Nil(t, result)
				return
			}
			// Migration requests are consumed without minting or refunding tokens.
			txs, compaction := node.checkSafeTokenMigration(ctx, req)
			require.Empty(t, txs)
			require.Empty(t, compaction)
			stored, err := node.store.ReadRequest(ctx, req.Id)
			require.NoError(t, err)
			require.Equal(t, uint8(common.RequestStateFailed), stored.State)
			result, handled, err := node.store.ReadActionResult(ctx, out.OutputId, req.Id)
			require.NoError(t, err)
			require.True(t, handled)
			require.NotNil(t, result)
			require.Equal(t, req.Id, result.RequestId)
			require.Empty(t, result.Transactions)
			if !test.missingSafe {
				storedSafe, err := node.store.ReadSafe(ctx, safe.Holder)
				require.NoError(t, err)
				require.Equal(t, safe, storedSafe)
			}
			if test.tokenBalance {
				balance, err := node.store.ReadEthereumBalance(ctx, safe.Address, underlying.String(), assetID)
				require.NoError(t, err)
				require.Equal(t, "10", balance.BigBalance().String())
			}
		})
	}
}

func assertFactoryCall(t *testing.T, method string, params []json.RawMessage, factory, asset string) bool {
	t.Helper()
	if method != "eth_call" || len(params) != 2 {
		t.Errorf("unexpected factory RPC: %s %s", method, params)
		return false
	}
	var call map[string]string
	if err := json.Unmarshal(params[0], &call); err != nil {
		t.Errorf("decode factory call parameters: %v", err)
		return false
	}
	if !strings.EqualFold(call["to"], factory) || !strings.HasSuffix(call["input"], strings.TrimPrefix(asset, "0x")) {
		t.Errorf("unexpected factory call parameters: %v", call)
		return false
	}
	return true
}
