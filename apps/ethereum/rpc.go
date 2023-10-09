package ethereum

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type RPCBlock struct {
	Hash   string   `json:"hash"`
	Number string   `json:"number"`
	Tx     []string `json:"transactions"`

	Height uint64
}

func RPCGetBlock(rpc, hash string) (*RPCBlock, error) {
	res, err := callEthereumRPCUntilSufficient(rpc, "eth_getBlockByHash", []any{hash, 1})
	if err != nil {
		return nil, err
	}
	var b RPCBlock
	err = json.Unmarshal(res, &b)
	if err != nil {
		return nil, err
	}
	height, success := new(big.Int).SetString(b.Number, 16)
	if !success {
		return nil, fmt.Errorf("Failed to parse ethereum block number")
	}
	b.Height = height.Uint64()
	return &b, err
}

func callEthereumRPCUntilSufficient(rpc, method string, params []any) ([]byte, error) {
	for {
		res, err := callEthereumRPC(rpc, method, params)
		if err != nil && strings.Contains(err.Error(), "Client.Timeout") {
			time.Sleep(7 * time.Second)
			continue
		}
		return res, err
	}
}

func callEthereumRPC(rpc, method string, params []any) ([]byte, error) {
	client := &http.Client{Timeout: 20 * time.Second}

	body, err := json.Marshal(map[string]any{
		"method":  method,
		"params":  params,
		"id":      time.Now().UnixNano(),
		"jsonrpc": "2.0",
	})
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("POST", rpc, bytes.NewReader(body))
	if err != nil {
		return nil, buildRPCError(rpc, method, params, err)
	}

	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, buildRPCError(rpc, method, params, err)
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, buildRPCError(rpc, method, params, err)
	}
	var result struct {
		Data  any `json:"result"`
		Error any `json:"error"`
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("%v (%s)", buildRPCError(rpc, method, params, err), string(body))
	}
	if result.Error != nil {
		return nil, fmt.Errorf("%v (%s)", buildRPCError(rpc, method, params, err), string(body))
	}

	return json.Marshal(result.Data)
}

func buildRPCError(rpc, method string, params []any, err error) error {
	return fmt.Errorf("callEthereumRPC(%s, %s, %v) => %v", rpc, method, params, err)
}
