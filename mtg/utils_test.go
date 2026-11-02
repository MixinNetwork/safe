package mtg

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

func TestInsufficientInputsReturnError(t *testing.T) {
	group := &Group{}
	tx := &Transaction{Amount: "2", Destination: sql.NullString{String: "destination", Valid: true}}
	_, _, err := group.getTransactionInputsAndRecipients(t.Context(), tx, []*UnifiedOutput{{Amount: decimal.NewFromInt(1)}})
	require.ErrorContains(t, err, "insufficient")
}

func TestGhostKeysRejectMalformedResponses(t *testing.T) {
	for _, data := range []string{"null", "[]", "[null]", "[{},{}]", "[{}]"} {
		t.Run(data, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Request-Id", r.Header.Get("X-Request-Id"))
				_, _ = io.WriteString(w, `{"data":`+data+`}`)
			}))
			t.Cleanup(server.Close)
			resty := mixin.GetRestyClient()
			previous := resty.BaseURL
			resty.SetBaseURL(server.URL)
			t.Cleanup(func() { resty.SetBaseURL(previous) })
			group := &Group{mixin: mixin.NewFromAccessToken("test")}
			address := mixin.RequireNewMixAddress([]string{"0ca34767-3a70-4a28-afd9-51c9bce4ecf5"}, 1)
			_, err := group.createGhostKeysUntilSufficient(context.Background(), &Transaction{TraceId: "trace"}, []*TransactionRecipient{{MixAddress: address, UuidMember: true}})
			require.ErrorContains(t, err, "ghost keys")
		})
	}
}
