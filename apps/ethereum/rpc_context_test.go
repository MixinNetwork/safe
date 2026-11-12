package ethereum

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MixinNetwork/safe/apps/ethereum/abi"
	ga "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/require"
)

func TestEthereumRPCContext(t *testing.T) {
	for _, call := range []struct {
		name string
		run  func(context.Context, string) error
	}{
		{"block", func(ctx context.Context, rpc string) error { _, err := RPCGetBlock(ctx, rpc, "hash"); return err }},
		{"height", func(ctx context.Context, rpc string) error { _, err := RPCGetBlockHeight(ctx, rpc); return err }},
		{"block by height", func(ctx context.Context, rpc string) error { _, err := RPCGetBlockByHeight(ctx, rpc, 42); return err }},
		{"full block", func(ctx context.Context, rpc string) error {
			_, err := RPCGetBlockWithTransactions(ctx, rpc, 42)
			return err
		}},
		{"gas price", func(ctx context.Context, rpc string) error { _, err := RPCGetGasPrice(ctx, rpc); return err }},
		{"transaction", func(ctx context.Context, rpc string) error {
			_, err := RPCGetTransactionByHash(ctx, rpc, "hash")
			return err
		}},
		{"transaction trace", func(ctx context.Context, rpc string) error {
			_, err := RPCDebugTraceTransactionByHash(ctx, rpc, "hash")
			return err
		}},
		{"block trace", func(ctx context.Context, rpc string) error {
			_, err := RPCDebugTraceBlockByNumber(ctx, rpc, 42)
			return err
		}},
		{"native balance", func(ctx context.Context, rpc string) error {
			_, err := RPCGetAssetBalanceAtBlock(ctx, rpc, securityTestSafe, EthereumEmptyAddress, 42)
			return err
		}},
	} {
		for _, stage := range []string{"before request", "retry wait", "request", "response body"} {
			t.Run(call.name+"/"+stage, func(t *testing.T) {
				var calls atomic.Int32
				release := make(chan struct{})
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if stage == "retry wait" {
						http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
						return
					}
					if stage == "response body" {
						fmt.Fprint(w, `{"result":`)
						w.(http.Flusher).Flush()
					}
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
				err := call.run(ctx, server.URL)
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
}

func TestEthereumContractCallsHonorContext(t *testing.T) {
	tokenABI, err := ga.JSON(strings.NewReader(abi.AssetABI))
	require.NoError(t, err)
	safeABI, err := ga.JSON(strings.NewReader(abi.GnosisSafeABI))
	require.NoError(t, err)
	guardABI, err := ga.JSON(strings.NewReader(abi.MixinSafeGuardABI))
	require.NoError(t, err)
	tx, err := CreateTransaction(t.Context(), TypeETHTx, 1, securityTestRequestID, securityTestSafe,
		securityTestReceiver, EthereumEmptyAddress, "1", big.NewInt(0))
	require.NoError(t, err)
	tx.Signatures[0], tx.Signatures[1] = make([]byte, 65), make([]byte, 65)
	for _, call := range []struct {
		name   string
		method string
		run    func(context.Context, string) error
	}{
		{"token balance", "balanceOf", func(ctx context.Context, rpc string) error {
			_, err := RPCGetAssetBalanceAtBlock(ctx, rpc, securityTestSafe, securityTestReceiver, 42)
			return err
		}},
		{"token name", "name", func(ctx context.Context, rpc string) error {
			_, err := FetchAsset(ctx, ChainEthereum, rpc, securityTestReceiver)
			return err
		}},
		{"token symbol", "symbol", func(ctx context.Context, rpc string) error {
			_, err := FetchAsset(ctx, ChainEthereum, rpc, securityTestReceiver)
			return err
		}},
		{"token decimals", "decimals", func(ctx context.Context, rpc string) error {
			_, err := FetchAsset(ctx, ChainEthereum, rpc, securityTestReceiver)
			return err
		}},
		{"safe guard", "getStorageAt", func(ctx context.Context, rpc string) error {
			_, err := GetSafeAccountGuard(ctx, 1, rpc, securityTestSafe)
			return err
		}},
		{"safe last transaction", "safeLastTxTime", func(ctx context.Context, rpc string) error {
			_, err := GetSafeLastTxTime(ctx, 1, rpc, securityTestSafe)
			return err
		}},
		{"safe nonce", "nonce", func(ctx context.Context, rpc string) error {
			_, err := FetchSafeNonce(ctx, 1, rpc, securityTestSafe, 42)
			return err
		}},
		{"safe validation", "execTransaction", tx.ValidTransaction},
		{"transaction gas price", "eth_gasPrice", func(ctx context.Context, rpc string) error {
			_, err := tx.BuildTransaction(ctx, rpc, strings.Repeat("01", 32))
			return err
		}},
		{"transaction gas tip", "eth_maxPriorityFeePerGas", func(ctx context.Context, rpc string) error {
			_, err := tx.BuildTransaction(ctx, rpc, strings.Repeat("01", 32))
			return err
		}},
		{"transfer logs", "eth_getLogs", func(ctx context.Context, rpc string) error {
			_, err := GetERC20TransferLogFromBlock(ctx, rpc, ChainEthereum, 42)
			return err
		}},
		{"accountant balance", "eth_getBalance", func(ctx context.Context, rpc string) error {
			_, err := FetchBalanceFromKey(ctx, rpc, strings.Repeat("01", 32))
			return err
		}},
	} {
		for _, canceled := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/canceled=%t", call.name, canceled), func(t *testing.T) {
				var calls, blocked atomic.Int32
				release := make(chan struct{})
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					var request ethereumRPCTestRequest
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
						return
					}
					method := request.Method
					var contractMethod *ga.Method
					if method == "eth_call" {
						var args struct{ Input, Data string }
						require.NoError(t, json.Unmarshal(request.Params[0], &args))
						data, err := hex.DecodeString(strings.TrimPrefix(args.Input+args.Data, "0x"))
						require.NoError(t, err)
						for _, contract := range []ga.ABI{tokenABI, safeABI, guardABI} {
							if m, err := contract.MethodById(data); err == nil {
								contractMethod, method = m, m.Name
								break
							}
						}
					}
					if method == call.method {
						blocked.Add(1)
						<-release
						return
					}
					var result string
					switch method {
					case "eth_chainId":
						result = "0x1"
					case "eth_blockNumber":
						result = "0x2a"
					case "eth_gasPrice":
						result = "0x64"
					case "name", "symbol", "getStorageAt":
						var value any = "Token"
						if method == "getStorageAt" {
							value = make([]byte, 32)
							value.([]byte)[31] = 1
						}
						encoded, err := contractMethod.Outputs.Pack(value)
						require.NoError(t, err)
						result = "0x" + hex.EncodeToString(encoded)
					default:
						t.Errorf("unexpected RPC method %s", method)
					}
					require.NoError(t, json.NewEncoder(w).Encode(ethereumRPCTestResponse{JSONRPC: "2.0", ID: request.ID, Result: result}))
				}))
				t.Cleanup(server.Close)
				defer close(release)
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				defer cancel()
				wantErr := context.DeadlineExceeded
				if canceled {
					cancel()
					wantErr = context.Canceled
				}
				start := time.Now()
				err := call.run(ctx, server.URL)
				require.ErrorIs(t, err, wantErr)
				require.Less(t, time.Since(start), 750*time.Millisecond)
				if canceled {
					require.Zero(t, calls.Load())
				} else {
					require.Equal(t, int32(1), blocked.Load())
				}
			})
		}
	}
}

func TestVerifyDepositHonorsContextAtEveryRPCStage(t *testing.T) {
	const hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const value = "0xde0b6b3a7640000"
	amount := big.NewInt(1_000_000_000_000_000_000)
	for _, stage := range []string{"eth_getTransactionByHash", "debug_traceTransaction", "eth_getLogs", "eth_getBalance/0x29", "eth_getBalance/0x2a"} {
		t.Run(stage, func(t *testing.T) {
			var blocked atomic.Int32
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request ethereumRPCTestRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					return
				}
				method := request.Method
				if method == "eth_getBalance" {
					var block string
					require.NoError(t, json.Unmarshal(request.Params[1], &block))
					method += "/" + block
				}
				if method == stage {
					blocked.Add(1)
					<-release
					return
				}
				var result any
				switch method {
				case "eth_getTransactionByHash":
					result = &RPCTransaction{Hash: hash, BlockNumber: "0x2a"}
				case "debug_traceTransaction":
					result = &RPCTransactionCallTrace{Type: "CALL", From: securityTestSafe, To: securityTestReceiver, Value: value}
				case "eth_getLogs":
					result = []any{}
				case "eth_getBalance/0x29":
					result = "0x0"
				default:
					t.Errorf("unexpected RPC method %s", method)
				}
				require.NoError(t, json.NewEncoder(w).Encode(ethereumRPCTestResponse{JSONRPC: "2.0", ID: request.ID, Result: result}))
			}))
			t.Cleanup(server.Close)
			defer close(release)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, _, err := VerifyDeposit(ctx, ChainEthereum, server.URL, hash, "ethereum", EthereumEmptyAddress,
				securityTestReceiver, ValuePrecision, 0, amount)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.Less(t, time.Since(start), 750*time.Millisecond)
			require.Equal(t, int32(1), blocked.Load())
		})
	}
}

func TestEthereumWebsocketDialHonorsContext(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	t.Cleanup(server.Close)
	defer close(release)
	rpc := "ws" + strings.TrimPrefix(server.URL, "http")
	for _, call := range []struct {
		name string
		run  func(context.Context) error
	}{
		{"safe", func(ctx context.Context) error { _, _, err := safeInit(ctx, 1, rpc, securityTestSafe); return err }},
		{"factory", func(ctx context.Context) error { _, _, err := factoryInit(ctx, rpc); return err }},
		{"guard", func(ctx context.Context) error { _, _, err := guardInit(ctx, rpc, securityTestSafe); return err }},
	} {
		t.Run(call.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			err := call.run(ctx)
			// The WebSocket dialer can report the socket deadline as a timeout.
			var timeout net.Error
			require.ErrorAs(t, err, &timeout)
			require.True(t, timeout.Timeout())
			require.Less(t, time.Since(start), 750*time.Millisecond)
		})
	}
}
