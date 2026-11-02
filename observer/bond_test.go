package observer

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MixinNetwork/safe/common"
	"github.com/stretchr/testify/require"
)

func TestObserverAssetLookupDecodesResponses(t *testing.T) {
	for _, test := range []struct {
		name    string
		body    string
		failure bool
		assetID string
	}{
		{"missing asset", `{"data":null}`, false, ""},
		{"malformed JSON", `{`, true, ""},
		{"valid asset", fmt.Sprintf(`{"data":{"asset_id":%q,"chain_id":%q}}`, common.SafeBitcoinChainId, common.SafeBitcoinChainId), false, common.SafeBitcoinChainId},
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
			if test.assetID == "" {
				require.Nil(t, asset)
			} else {
				require.NotNil(t, asset)
				require.Equal(t, test.assetID, asset.AssetId)
				require.Equal(t, byte(common.SafeChainBitcoin), asset.Chain)
			}
		})
	}
}
