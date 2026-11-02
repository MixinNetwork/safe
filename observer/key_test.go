package observer

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/stretchr/testify/require"
)

func TestFailedObserverKeySubmission(t *testing.T) {
	f := newTransactionHTTPFixture(t)
	const public = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	code := strings.Repeat("01", 32)
	require.NoError(t, f.node.store.WriteObserverKeys(t.Context(), common.CurveSecp256k1ECDSABitcoin, map[string]string{public: code}))
	f.node.conf = &Configuration{KeeperAppId: f.requestID}
	f.node.conf.App.AppId = f.accountID
	f.node.keeper = &mtg.Configuration{}
	f.node.keeper.Genesis.Members = []string{f.requestID}
	f.node.keeper.Genesis.Threshold = 1
	f.node.mixin = mixin.NewFromAccessToken("test")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", r.Header.Get("X-Request-Id"))
		fmt.Fprint(w, `{"error":{"code":400,"description":"rejected key submission"}}`)
	}))
	t.Cleanup(server.Close)
	resty := mixin.GetRestyClient()
	previous := resty.BaseURL
	resty.SetBaseURL(server.URL)
	t.Cleanup(func() { resty.SetBaseURL(previous) })

	err := f.node.safeAddObserverKeys(t.Context(), common.SafeChainBitcoin)
	require.ErrorContains(t, err, "rejected key submission")
	stored, chainCode, err := f.node.store.ReadObserverKey(t.Context(), common.CurveSecp256k1ECDSABitcoin)
	require.NoError(t, err)
	require.Empty(t, stored)
	require.Nil(t, chainCode)
}
