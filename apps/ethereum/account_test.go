package ethereum

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSafeRPCRejectsOverflowingChainIDsAndNonces(t *testing.T) {
	for _, name := range []string{"valid", "chain overflow", "nonce overflow", "future height", "negative height"} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Method string
					ID     json.RawMessage
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				var result string
				switch request.Method {
				case "eth_chainId":
					result = "0x1"
					if name == "chain overflow" {
						result = "0x10000000000000001"
					}
				case "eth_blockNumber":
					result = "0x10"
				case "eth_call":
					nonce := big.NewInt(42)
					if name == "nonce overflow" {
						nonce.SetUint64(uint64(math.MaxInt64) + 1)
					}
					result = fmt.Sprintf("0x%064x", nonce)
				default:
					t.Errorf("unexpected method %s", request.Method)
				}
				require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result}))
			}))
			defer server.Close()
			height := int64(10)
			if name == "future height" {
				height = 17
			}
			if name == "negative height" {
				height = -1
			}
			nonce, err := FetchSafeNonce(t.Context(), 1, server.URL, securityTestSafe, height)
			if name == "valid" {
				require.NoError(t, err)
				require.Equal(t, int64(42), nonce)
			} else {
				require.Error(t, err)
			}
		})
	}
}
