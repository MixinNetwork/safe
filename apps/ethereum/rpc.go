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
	Hash      string   `json:"hash"`
	Number    string   `json:"number"`
	Tx        []string `json:"transactions"`
	Timestamp string   `json:"timestamp"`

	Height uint64
	Time   time.Time
}

type RPCBlockWithTransactions struct {
	Hash   string           `json:"hash"`
	Number string           `json:"number"`
	Tx     []RPCTransaction `json:"transactions"`

	Height uint64
}

type RPCTransaction struct {
	BlockHash        string `json:"blockHash"`
	BlockNumber      string `json:"blockNumber"`
	ChainID          string `json:"chainId"`
	From             string `json:"from"`
	Gas              string `json:"gas"`
	GasPrice         string `json:"gasPrice"`
	Hash             string `json:"hash"`
	Input            string `json:"input"`
	Nonce            string `json:"Nonce"`
	To               string `json:"to"`
	TransactionIndex string `json:"transactionIndex"`
	Type             string `json:"type"`
	Value            string `json:"value"`

	BlockHeight uint64
}

func RPCGetBlock(rpc, hash string) (*RPCBlock, error) {
	if !strings.HasPrefix(hash, "0x") {
		hash = "0x" + hash
	}
	res, err := callEthereumRPCUntilSufficient(rpc, "eth_getBlockByHash", []any{hash, false})
	if err != nil {
		return nil, err
	}
	var b RPCBlock
	err = json.Unmarshal(res, &b)
	if err != nil {
		return nil, err
	}
	blockHeight, err := ethereumNumberToUint64(b.Number)
	if err != nil {
		return nil, err
	}
	b.Height = blockHeight
	timestamp, err := ethereumNumberToUint64(b.Timestamp)
	if err != nil {
		return nil, err
	}
	b.Time = time.Unix(int64(timestamp), 0)
	return &b, err
}

func RPCGetBlockWithTransactions(rpc, hash string) (*RPCBlockWithTransactions, error) {
	if !strings.HasPrefix(hash, "0x") {
		hash = "0x" + hash
	}
	res, err := callEthereumRPCUntilSufficient(rpc, "eth_getBlockByHash", []any{hash, true})
	if err != nil {
		return nil, err
	}
	var b RPCBlockWithTransactions
	err = json.Unmarshal(res, &b)
	if err != nil {
		return nil, err
	}
	blockHeight, err := ethereumNumberToUint64(b.Number)
	if err != nil {
		return nil, err
	}
	b.Height = blockHeight
	for _, tx := range b.Tx {
		tx.BlockHash = hash
	}
	return &b, err
}

func RPCGetAddressBalance(rpc, txHash, address string) (*big.Int, error) {
	tx, err := RPCGetTransactionByHash(rpc, txHash)
	if err != nil {
		return nil, err
	}
	res, err := callEthereumRPCUntilSufficient(rpc, "eth_getBalance", []any{address, tx.BlockHash})
	if err != nil {
		return nil, err
	}
	var b string
	err = json.Unmarshal(res, &b)
	if err != nil {
		return nil, err
	}
	balance, success := new(big.Int).SetString(b[2:], 16)
	if !success {
		return nil, fmt.Errorf("Failed to parse address balance")
	}
	return balance, err
}

func RPCGetTransactionByHash(rpc, hash string) (*RPCTransaction, error) {
	if !strings.HasPrefix(hash, "0x") {
		hash = "0x" + hash
	}
	res, err := callEthereumRPCUntilSufficient(rpc, "eth_getTransactionByHash", []any{hash})
	if err != nil {
		return nil, err
	}
	var b RPCTransaction
	err = json.Unmarshal(res, &b)
	if err != nil {
		return nil, err
	}
	blockHeight, err := ethereumNumberToUint64(b.BlockNumber)
	if err != nil {
		return nil, err
	}
	b.BlockHeight = blockHeight
	return &b, err
}

func RPCGetAddressBalanceAtBlock(rpc, blockHash, address string) (*big.Int, error) {
	res, err := callEthereumRPCUntilSufficient(rpc, "eth_getBalance", []any{address, blockHash})
	if err != nil {
		return nil, err
	}
	var b string
	err = json.Unmarshal(res, &b)
	if err != nil {
		return nil, err
	}
	balance, success := new(big.Int).SetString(b[2:], 16)
	if !success {
		return nil, fmt.Errorf("Failed to parse address balance")
	}
	return balance, err
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

func ethereumNumberToUint64(hex string) (uint64, error) {
	if !strings.HasPrefix(hex, "0x") {
		return 0, fmt.Errorf("invalid hex %s", hex)
	}
	value, success := new(big.Int).SetString(hex, 0)
	if !success {
		return 0, fmt.Errorf("invalid hex %s", hex)
	}
	if !value.IsUint64() {
		return 0, fmt.Errorf("invalid uint64 %s", hex)
	}
	return value.Uint64(), nil
}
