package keeper

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MixinNetwork/safe/common"
	"github.com/stretchr/testify/require"
)

func TestKeeperAssetLookupDecodesResponses(t *testing.T) {
	for _, test := range []struct {
		name    string
		body    string
		failure bool
		found   bool
	}{
		{"invalid JSON", `{`, true, false},
		{"valid asset", `{"data":{"asset_id":"c6d0c728-2624-429b-8e0d-d9d19b6592fa","chain_id":"c6d0c728-2624-429b-8e0d-d9d19b6592fa"}}`, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			node := &Node{conf: &Configuration{MixinMessengerAPI: server.URL}}
			asset, err := node.fetchMixinAsset(t.Context(), common.SafeBitcoinChainId)
			if test.failure {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if test.found {
				require.NotNil(t, asset)
				require.Equal(t, common.SafeBitcoinChainId, asset.AssetId)
				require.Equal(t, byte(common.SafeChainBitcoin), asset.Chain)
			} else {
				require.Nil(t, asset)
			}
		})
	}
}

func TestFetchAssetMetaHonorsCanceledContext(t *testing.T) {
	store, err := OpenSQLite3Store(t.TempDir() + "/keeper.sqlite3")
	require.NoError(t, err)
	defer store.Close()
	node := &Node{store: store}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = node.fetchAssetMeta(ctx, "missing")
	require.ErrorIs(t, err, context.Canceled)
}
