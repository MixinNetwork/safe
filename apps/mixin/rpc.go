package mixin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/logger"
)

type WithdrawalData struct {
	Address string `json:"address"`
	Tag     string `json:"tag"`
}

type Output struct {
	Type       uint8           `json:"type"`
	Amount     string          `json:"amount"`
	Withdrawal *WithdrawalData `json:"withdrawal"`
}

type RPCTransaction struct {
	Asset      string   `json:"asset"`
	Extra      string   `json:"extra"`
	Hash       string   `json:"hash"`
	Output     []Output `json:"outputs"`
	References []string `json:"references"`
}

type RPCSnapshot struct {
	Hash        string           `json:"hash"`
	Hex         string           `json:"hex"`
	Transaction []RPCTransaction `json:"transactions"`
	Topology    uint64           `json:"topology"`
}

func RPCGetTransaction(ctx context.Context, rpc, hash string) (*RPCTransaction, error) {
	res, err := callMixinRPCUntilSufficient(rpc, "gettransaction", []any{hash})
	if err != nil {
		return nil, err
	}
	var r *RPCTransaction
	err = json.Unmarshal(res, &r)
	return r, err
}

func RPCListSnapshots(ctx context.Context, rpc string, offset uint64, limit int) ([]RPCSnapshot, error) {
	res, err := callMixinRPCUntilSufficient(rpc, "listsnapshots", []any{fmt.Sprint(offset), fmt.Sprint(limit), "false", "true"})
	if err != nil {
		return nil, err
	}
	var r []RPCSnapshot
	err = json.Unmarshal(res, &r)
	if err != nil {
		return nil, err
	}
	return r, err
}

func callMixinRPCUntilSufficient(rpc, method string, params []any) ([]byte, error) {
	for {
		res, err := callMixinRPC(rpc, method, params)
		if err == nil {
			return res, nil
		}
		logger.Printf("callMixinRPC(%s, %s, %v) => %v", rpc, method, params, err)
		reason := strings.ToLower(err.Error())
		switch {
		case strings.Contains(reason, "timeout"):
		case strings.Contains(reason, "eof"):
		case strings.Contains(reason, "handshake"):
		case strings.Contains(reason, "invalid character '<'"):
		default:
			return res, err
		}
		time.Sleep(7 * time.Second)
	}
}

func callMixinRPC(rpc, method string, params []any) ([]byte, error) {
	client := &http.Client{Timeout: 20 * time.Second}

	body, err := json.Marshal(map[string]any{
		"method":  method,
		"params":  params,
		"id":      fmt.Sprint(time.Now().UnixNano()),
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
		Data  any `json:"data"`
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
	return fmt.Errorf("callMixinRPC(%s, %s, %v) => %v", rpc, method, params, err)
}
