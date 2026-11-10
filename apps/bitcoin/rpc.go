package bitcoin

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/util"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/shopspring/decimal"
)

type scriptPubKey struct {
	Hex             string   `json:"hex"`
	Type            string   `json:"type"`
	Address         string   `json:"address"`
	LegacyAddresses []string `json:"addresses"`
}

type rpcIn struct {
	Coinbase string `json:"coinbase"`
	TxId     string `json:"txid"`
	VOUT     int64  `json:"vout"`
}

type rpcOut struct {
	Value        float64       `json:"value"`
	N            int64         `json:"n"`
	ScriptPubKey *scriptPubKey `json:"scriptPubKey"`
}

type RPCTransaction struct {
	TxId      string    `json:"txid"`
	Vin       []*rpcIn  `json:"vin"`
	Vout      []*rpcOut `json:"vout"`
	BlockHash string    `json:"blockhash"`
	Hex       string    `json:"hex"`
	Fee       float64   `json:"fee"`
	VSize     int64     `json:"vsize"`
}

type MemPoolTransaction struct {
	Fees struct {
		Base float64 `json:"base"`
	} `json:"fees"`
	VSize int64 `json:"vsize"`
	Time  int64 `json:"time"`
}

type RPCBlock struct {
	Hash          string   `json:"hash"`
	Height        uint64   `json:"height"`
	Tx            []string `json:"tx"`
	Confirmations int      `json:"confirmations"`
}

type RPCBlockWithTransactions struct {
	Hash   string            `json:"hash"`
	Height uint64            `json:"height"`
	Tx     []*RPCTransaction `json:"tx"`
}

func RPCGetTransactionOutput(ctx context.Context, chain byte, rpc, hash string, index int64) (*RPCTransaction, *Output, error) {
	if index < 0 {
		return nil, nil, fmt.Errorf("invalid output index %d", index)
	}
	tx, err := RPCGetTransaction(ctx, chain, rpc, hash)
	if err != nil {
		return nil, nil, err
	}
	if int64(len(tx.Vout)) <= index {
		return nil, nil, nil
	}
	out := tx.Vout[index]
	if out == nil || out.ScriptPubKey == nil {
		return nil, nil, fmt.Errorf("missing output script %s:%d", hash, index)
	}
	skt := out.ScriptPubKey.Type
	if skt != ScriptPubKeyTypeWitnessScriptHash && skt != ScriptPubKeyTypeWitnessKeyHash {
		return nil, nil, nil
	}
	if out.ScriptPubKey.Address == "" {
		return nil, nil, nil
	}

	satoshi := decimal.NewFromFloat(out.Value).Mul(decimal.NewFromFloat(ValueSatoshi))
	if !satoshi.IsInteger() || !satoshi.BigInt().IsInt64() {
		return nil, nil, nil
	}
	output := &Output{
		Address:  out.ScriptPubKey.Address,
		Satoshi:  satoshi.IntPart(),
		Coinbase: len(tx.Vin) > 0 && tx.Vin[0] != nil && tx.Vin[0].Coinbase != "",
	}

	if tx.BlockHash == "" { // mempool
		output.Height = ^uint64(0)
	} else {
		block, err := RPCGetBlock(ctx, rpc, tx.BlockHash)
		if err != nil {
			return nil, nil, err
		}
		output.Height = block.Height
	}

	rtb, err := hex.DecodeString(tx.Hex)
	if err != nil {
		return nil, nil, err
	}
	rtx, err := btcutil.NewTxFromBytes(rtb)
	if err != nil {
		return nil, nil, err
	}
	rtmx := rtx.MsgTx()
	if rtmx.TxHash().String() != hash {
		return nil, nil, nil
	}
	if len(rtmx.TxOut) != len(tx.Vout) {
		return nil, nil, nil
	}
	if rtmx.TxOut[index].Value != output.Satoshi {
		return nil, nil, nil
	}
	script, err := txscript.ParsePkScript(rtmx.TxOut[index].PkScript)
	if err != nil {
		return nil, nil, err
	}
	addr, err := script.Address(NetConfig(chain))
	if err != nil {
		return nil, nil, err
	}
	if addr.EncodeAddress() != output.Address {
		return nil, nil, nil
	}

	return tx, output, nil
}

func RPCGetTransactionSender(ctx context.Context, chain byte, rpc string, tx *RPCTransaction) (string, error) {
	if tx == nil || len(tx.Vin) == 0 || tx.Vin[0] == nil {
		return "", fmt.Errorf("missing transaction input")
	}
	if tx.Vin[0].Coinbase != "" {
		return tx.Vin[0].Coinbase, nil
	}
	itx, err := RPCGetTransaction(ctx, chain, rpc, tx.Vin[0].TxId)
	if err != nil {
		return "", err
	}
	index := tx.Vin[0].VOUT
	if index < 0 || index >= int64(len(itx.Vout)) || itx.Vout[index] == nil || itx.Vout[index].ScriptPubKey == nil {
		return "", fmt.Errorf("invalid previous output %s:%d", tx.Vin[0].TxId, index)
	}
	return itx.Vout[index].ScriptPubKey.Address, nil
}

func RPCGetTransaction(ctx context.Context, chain byte, rpc, hash string) (*RPCTransaction, error) {
	res, err := callBitcoinRPCUntilSufficient(ctx, rpc, "getrawtransaction", []any{hash, 1})
	if err != nil {
		return nil, err
	}
	return parseRPCTransaction(chain, hash, res)
}

// RPCGetTransactionOnce performs one attempt so optional background scans
// can stop at their deadline without changing normal deposit retry behavior.
func RPCGetTransactionOnce(ctx context.Context, chain byte, rpc, hash string) (*RPCTransaction, error) {
	res, err := callBitcoinRPCWithContext(ctx, rpc, "getrawtransaction", []any{hash, 1})
	if err != nil {
		return nil, err
	}
	return parseRPCTransaction(chain, hash, res)
}

func parseRPCTransaction(chain byte, hash string, res []byte) (*RPCTransaction, error) {
	var tx *RPCTransaction
	err := json.Unmarshal(res, &tx)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, fmt.Errorf("missing transaction %s", hash)
	}
	if tx.TxId != hash {
		return nil, fmt.Errorf("unexpected transaction hash %s, expected %s", tx.TxId, hash)
	}
	fixLitecoinLegacyScriptPubKeyRPC(chain, tx)
	return tx, nil
}

// RPCGetMempoolTransactionIDs lists the newest transactions first, without
// fetching their bodies. getrawmempool's verbose result is metadata only.
func RPCGetMempoolTransactionIDs(ctx context.Context, rpc string) ([]string, error) {
	res, err := callBitcoinRPCWithContext(ctx, rpc, "getrawmempool", []any{true})
	if err != nil {
		return nil, err
	}
	var entries map[string]MemPoolTransaction
	if err := json.Unmarshal(res, &entries); err != nil {
		return nil, err
	}
	if entries == nil {
		return nil, fmt.Errorf("missing mempool")
	}
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if entries[ids[i]].Time == entries[ids[j]].Time {
			return ids[i] < ids[j]
		}
		return entries[ids[i]].Time > entries[ids[j]].Time
	})
	return ids, nil
}

func RPCGetRawMempoolWithTransactions(ctx context.Context, rpc string) ([]*RPCTransaction, error) {
	res, err := callBitcoinRPCUntilSufficient(ctx, rpc, "getrawmempool", []any{true})
	if err != nil {
		return nil, err
	}
	txMap := make(map[string]MemPoolTransaction)
	err = json.Unmarshal(res, &txMap)
	if err != nil {
		return nil, err
	}

	var transactions []*RPCTransaction
	for id, tx := range txMap {
		transactions = append(transactions, &RPCTransaction{
			TxId:  id,
			Fee:   tx.Fees.Base,
			VSize: tx.VSize,
		})
	}
	return transactions, nil
}

func RPCGetBlockWithTransactions(ctx context.Context, chain byte, rpc, hash string) (*RPCBlockWithTransactions, error) {
	res, err := callBitcoinRPCUntilSufficient(ctx, rpc, "getblock", []any{hash, 2})
	if err != nil {
		return nil, err
	}
	var b *RPCBlockWithTransactions
	err = json.Unmarshal(res, &b)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("missing block %s", hash)
	}
	if b.Hash != hash {
		return nil, fmt.Errorf("unexpected block hash %s, expected %s", b.Hash, hash)
	}
	for _, tx := range b.Tx {
		if tx == nil {
			return nil, fmt.Errorf("missing transaction in block %s", hash)
		}
		fixLitecoinLegacyScriptPubKeyRPC(chain, tx)
		tx.BlockHash = hash
	}
	return b, nil
}

func RPCGetBlockAverageFeePerBytes(ctx context.Context, chain byte, rpc string) (*big.Int, error) {
	height, err := RPCGetBlockHeight(ctx, rpc)
	if err != nil {
		return nil, err
	}
	hash, err := RPCGetBlockHash(ctx, rpc, height)
	if err != nil {
		return nil, err
	}
	block, err := RPCGetBlockWithTransactions(ctx, chain, rpc, hash)
	if err != nil {
		return nil, err
	}
	sum := decimal.NewFromInt(0)
	var count int64
	for _, tx := range block.Tx {
		if tx.VSize <= 0 {
			continue
		}
		fee := decimal.NewFromFloat(tx.Fee).Mul(decimal.New(1, 8))
		size := decimal.NewFromInt(tx.VSize)
		feePerBytes := fee.Div(size)
		sum = sum.Add(feePerBytes)
		count++
	}
	if count == 0 {
		return new(big.Int), nil
	}
	sum = sum.Div(decimal.NewFromInt(count))
	return sum.Ceil().BigInt(), nil
}

func RPCGetMempoolAverageFeePerBytes(ctx context.Context, rpc string) (*big.Int, error) {
	txs, err := RPCGetRawMempoolWithTransactions(ctx, rpc)
	if err != nil {
		return nil, err
	}
	fees := []decimal.Decimal{}
	for _, tx := range txs {
		if tx.VSize <= 0 {
			continue
		}
		fee := decimal.NewFromFloat(tx.Fee).Mul(decimal.New(1, 8))
		size := decimal.NewFromInt(tx.VSize)
		feePerBytes := fee.Div(size)
		fees = append(fees, feePerBytes)
	}
	sort.Slice(fees, func(i, j int) bool { return fees[i].Cmp(fees[j]) > 0 })
	sum := decimal.NewFromInt(0)
	var count int64
	for i, f := range fees {
		if i >= 2000 {
			break
		}
		sum = sum.Add(f)
		count += 1
	}
	if count == 0 {
		return new(big.Int), nil
	}
	avg := sum.Div(decimal.NewFromInt(count))
	return avg.Ceil().BigInt(), nil
}

func RPCGetBlock(ctx context.Context, rpc, hash string) (*RPCBlock, error) {
	res, err := callBitcoinRPCUntilSufficient(ctx, rpc, "getblock", []any{hash, 1})
	if err != nil {
		return nil, err
	}
	var b *RPCBlock
	err = json.Unmarshal(res, &b)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("missing block %s", hash)
	}
	if b.Hash != hash {
		return nil, fmt.Errorf("unexpected block hash %s, expected %s", b.Hash, hash)
	}
	return b, nil
}

func RPCGetBlockHash(ctx context.Context, rpc string, num int64) (string, error) {
	res, err := callBitcoinRPCUntilSufficient(ctx, rpc, "getblockhash", []any{num})
	if err != nil {
		return "", err
	}
	var hash string
	err = json.Unmarshal(res, &hash)
	return hash, err
}

func RPCGetBlockHeight(ctx context.Context, rpc string) (int64, error) {
	res, err := callBitcoinRPCUntilSufficient(ctx, rpc, "getblockchaininfo", []any{})
	if err != nil {
		return 0, err
	}
	var info struct {
		Blocks *int64 `json:"blocks"`
	}
	err = json.Unmarshal(res, &info)
	if err != nil {
		return 0, err
	}
	if info.Blocks == nil || *info.Blocks < 0 {
		return 0, fmt.Errorf("missing or invalid block height")
	}
	return *info.Blocks, nil
}

func EstimateAvgFee(ctx context.Context, chain byte, rpc string) (int64, error) {
	blockAvgFee, err := RPCGetBlockAverageFeePerBytes(ctx, chain, rpc)
	if err != nil {
		return 0, err
	}
	mempoolTopAvgFee, err := RPCGetMempoolAverageFeePerBytes(ctx, rpc)
	if err != nil {
		return 0, err
	}
	maxFee := blockAvgFee
	if mempoolTopAvgFee.Cmp(blockAvgFee) > 0 {
		maxFee = mempoolTopAvgFee
	}
	if maxFee.Sign() <= 0 || !maxFee.IsInt64() {
		return 0, fmt.Errorf("EstimateAvgFee(%d) => %s", chain, maxFee.String())
	}

	fvb := maxFee.Int64()
	if !CheckFeeRange(fvb, chain) {
		return 0, fmt.Errorf("CheckFeeRange(%d) => %d", chain, fvb)
	}
	fvb = max(fvb, 5)
	return fvb, nil
}

func RPCSendRawTransaction(ctx context.Context, rpc, raw string) (string, error) {
	res, err := callBitcoinRPCUntilSufficient(ctx, rpc, "sendrawtransaction", []any{raw})
	if err != nil {
		return "", err
	}
	var hash string
	err = json.Unmarshal(res, &hash)
	return hash, err
}

// FIXME wait for litecoin core update to the latest rpc
func fixLitecoinLegacyScriptPubKeyRPC(chain byte, tx *RPCTransaction) {
	switch chain {
	case ChainLitecoin:
		for _, o := range tx.Vout {
			if o == nil || o.ScriptPubKey == nil || len(o.ScriptPubKey.LegacyAddresses) != 1 {
				continue
			}
			o.ScriptPubKey.Address = o.ScriptPubKey.LegacyAddresses[0]
		}
	}
}

func callBitcoinRPCUntilSufficient(ctx context.Context, rpc, method string, params []any) ([]byte, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res, err := callBitcoinRPCWithContext(ctx, rpc, method, params)
		if err == nil {
			return res, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		logger.Printf("callBitcoinRPC(%s, %s, %v) => %v", rpc, method, params, err)
		if !util.CheckRetryableRPCError(err) {
			return res, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func callBitcoinRPCWithContext(ctx context.Context, rpc, method string, params []any) ([]byte, error) {
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

	req, err := http.NewRequestWithContext(ctx, "POST", rpc, bytes.NewReader(body))
	if err != nil {
		return nil, buildRPCError(rpc, method, params, err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, buildRPCError(rpc, method, params, err)
	}
	defer util.CloseOrPanic(resp.Body)

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, buildRPCError(rpc, method, params, err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, buildRPCError(rpc, method, params, &util.RPCResponseError{StatusCode: resp.StatusCode, Body: string(body)})
	}
	var result struct {
		Data  json.RawMessage `json:"result"`
		Error any             `json:"error"`
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("%v (%s)", buildRPCError(rpc, method, params, err), string(body))
	}
	if result.Error != nil {
		return nil, buildRPCError(rpc, method, params, &util.RPCResponseError{StatusCode: resp.StatusCode, Body: string(body)})
	}
	if len(result.Data) == 0 {
		return nil, buildRPCError(rpc, method, params, fmt.Errorf("missing RPC result"))
	}
	return result.Data, nil
}

func buildRPCError(rpc, method string, params []any, err error) error {
	return fmt.Errorf("callBitcoinRPC(%s, %s, %v) => %w", rpc, method, params, err)
}
