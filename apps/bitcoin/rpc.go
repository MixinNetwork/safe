package bitcoin

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

type scriptPubKey struct {
	Hex     string `json:"hex"`
	Type    string `json:"type"`
	Address string `json:"address"`
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
}

type RPCBlock struct {
	Hash   string   `json:"hash"`
	Height uint64   `json:"height"`
	Tx     []string `json:"tx"`
}

type RPCBlockWithTransactions struct {
	Hash   string            `json:"hash"`
	Height uint64            `json:"height"`
	Tx     []*RPCTransaction `json:"tx"`
}

func RPCGetTransactionOutput(rpc, hash string, index int64) (*Output, error) {
	tx, err := RPCGetTransaction(rpc, hash)
	if err != nil {
		return nil, err
	}
	if int64(len(tx.Vout)) <= index {
		return nil, nil
	}
	out := tx.Vout[index]
	skt := out.ScriptPubKey.Type
	if skt != ScriptPubKeyTypeWitnessKeyHash && skt != ScriptPubKeyTypeWitnessScriptHash {
		return nil, nil
	}

	output := &Output{
		Address:  out.ScriptPubKey.Address,
		Satoshi:  int64(out.Value * float64(ValueSatoshi)),
		Coinbase: len(tx.Vin) == 0 && tx.Vin[0].Coinbase != "",
	}

	if tx.BlockHash == "" { // mempool
		output.Height = ^uint64(0)
	} else {
		block, err := RPCGetBlock(rpc, tx.BlockHash)
		if err != nil {
			return nil, err
		}
		output.Height = block.Height
	}

	rtb, err := hex.DecodeString(tx.Hex)
	if err != nil {
		return nil, err
	}
	rtx, err := btcutil.NewTxFromBytes(rtb)
	if err != nil {
		return nil, err
	}
	rtmx := rtx.MsgTx()
	if rtmx.TxHash().String() != hash {
		return nil, nil
	}
	if len(rtmx.TxOut) != len(tx.Vout) {
		return nil, nil
	}
	if rtmx.TxOut[index].Value != output.Satoshi {
		return nil, nil
	}
	script, err := txscript.ParsePkScript(rtmx.TxOut[index].PkScript)
	if err != nil {
		return nil, err
	}
	addr, err := script.Address(&chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	if addr.EncodeAddress() != output.Address {
		return nil, nil
	}

	return output, nil
}

func RPCGetTransaction(rpc, hash string) (*RPCTransaction, error) {
	res, err := callBitcoinRPC(rpc, "getrawtransaction", []any{hash, 1})
	if err != nil {
		return nil, err
	}
	var tx RPCTransaction
	err = json.Unmarshal(res, &tx)
	return &tx, err
}

func RPCGetRawMempool(rpc string) ([]*RPCTransaction, error) {
	res, err := callBitcoinRPC(rpc, "getrawmempool", []any{})
	if err != nil {
		return nil, err
	}
	var txs []string
	err = json.Unmarshal(res, &txs)
	if err != nil {
		return nil, err
	}

	var transactions []*RPCTransaction
	for _, id := range txs {
		tx, err := RPCGetTransaction(rpc, id)
		if err != nil || tx == nil {
			logger.Printf("bitcoin.RPCGetRawMempool(%s) => %v %v", id, tx, err)
			continue
		}
		transactions = append(transactions, tx)
	}
	return transactions, nil
}

func RPCGetBlockWithTransactions(rpc, hash string) (*RPCBlockWithTransactions, error) {
	res, err := callBitcoinRPC(rpc, "getblock", []any{hash, 2})
	if err != nil {
		return nil, err
	}
	var b RPCBlockWithTransactions
	err = json.Unmarshal(res, &b)
	if err != nil {
		return nil, err
	}
	for _, tx := range b.Tx {
		tx.BlockHash = hash
	}
	return &b, err
}

func RPCGetBlock(rpc, hash string) (*RPCBlock, error) {
	res, err := callBitcoinRPC(rpc, "getblock", []any{hash, 1})
	if err != nil {
		return nil, err
	}
	var b RPCBlock
	err = json.Unmarshal(res, &b)
	return &b, err
}

func RPCGetBlockHash(rpc string, num int64) (string, error) {
	res, err := callBitcoinRPC(rpc, "getblockhash", []any{num})
	if err != nil {
		return "", err
	}
	var hash string
	err = json.Unmarshal(res, &hash)
	return hash, err
}

func RPCGetBlockHeight(rpc string) (int64, error) {
	res, err := callBitcoinRPC(rpc, "getblockchaininfo", []any{})
	if err != nil {
		return 0, err
	}
	var info struct {
		Blocks int64 `json:"blocks"`
	}
	err = json.Unmarshal(res, &info)
	return info.Blocks, err
}

func RPCEstimateSmartFee(rpc string) (int64, error) {
	res, err := callBitcoinRPC(rpc, "estimatesmartfee", []any{1})
	if err != nil {
		return 0, err
	}
	var fee struct {
		Rate float64 `json:"feerate"`
	}
	err = json.Unmarshal(res, &fee)
	if err != nil || fee.Rate <= 0 {
		return 0, fmt.Errorf("estimatesmartfee %f %v", fee.Rate, err)
	}
	fvb := int64(fee.Rate * 1.1 * ValueSatoshi / 1024)
	if fvb < 10 {
		fvb = 10
	}
	return fvb, nil
}

func RPCSendRawTransaction(rpc, raw string) (string, error) {
	res, err := callBitcoinRPC(rpc, "sendrawtransaction", []any{raw})
	if err != nil {
		return "", err
	}
	var hash string
	err = json.Unmarshal(res, &hash)
	return hash, err
}

func callBitcoinRPC(node, method string, params []any) ([]byte, error) {
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

	req, err := http.NewRequest("POST", node, bytes.NewReader(body))
	if err != nil {
		return nil, buildRPCError(method, params, err)
	}

	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, buildRPCError(method, params, err)
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, buildRPCError(method, params, err)
	}
	var result struct {
		Data  any `json:"result"`
		Error any `json:"error"`
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("%v (%s)", buildRPCError(method, params, err), string(body))
	}
	if result.Error != nil {
		return nil, fmt.Errorf("%v (%s)", buildRPCError(method, params, err), string(body))
	}

	return json.Marshal(result.Data)
}

func buildRPCError(method string, params []any, err error) error {
	return fmt.Errorf("callBitcoinRPC(%s, %v) => %v", method, params, err)
}
