package observer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/stretchr/testify/require"
)

func TestObserverJSONErrorsContainReadableMessages(t *testing.T) {
	node := &Node{}
	for _, handler := range []func(http.ResponseWriter, *http.Request, map[string]string){
		node.httpApproveAccount, node.httpApproveTransaction, node.httpSignRecovery, node.httpCreateInheritanceTransaction,
	} {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{")), nil)
		require.Equal(t, http.StatusBadRequest, response.Code)
		var body struct {
			Error string `json:"error"`
		}
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
		require.NotEmpty(t, body.Error)
	}
}

func TestObserverChainListWaitsForOperationParameters(t *testing.T) {
	f := newTransactionHTTPFixture(t)
	_, err := f.keeperDB.ExecContext(t.Context(), `INSERT INTO network_infos
		(request_id,chain,fee,height,hash,created_at) VALUES ('head',?,1,100,'hash',?)`, common.SafeChainBitcoin, time.Now().Add(-time.Minute))
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodGet, "/chains", nil).WithContext(t.Context())
	w := httptest.NewRecorder()
	f.node.httpListChains(w, r, nil)
	require.Equal(t, http.StatusOK, w.Code)
}
