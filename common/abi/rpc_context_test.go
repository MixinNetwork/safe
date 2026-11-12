package abi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFactoryAssetLookupHonorsContext(t *testing.T) {
	InitFactoryContractAddress("0x4D17777E0AC12C6a0d4DEF1204278cFEAe142a1E")
	for _, stage := range []string{"before request", "contract call"} {
		t.Run(stage, func(t *testing.T) {
			var calls atomic.Int32
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				<-release
			}))
			t.Cleanup(server.Close)
			defer close(release)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			wantErr := context.DeadlineExceeded
			if stage == "before request" {
				cancel()
				wantErr = context.Canceled
			}
			start := time.Now()
			_, err := CheckFactoryAssetDeployed(ctx, server.URL, testReceiverAddress)
			require.ErrorIs(t, err, wantErr)
			require.Less(t, time.Since(start), 750*time.Millisecond)
			if stage == "before request" {
				require.Zero(t, calls.Load())
			} else {
				require.Equal(t, int32(1), calls.Load())
			}
		})
	}
}
