package common

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MixinNetwork/bot-api-go-client"
	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/shopspring/decimal"
)

// TODO the output should include the snapshot signature, then it can just be
// verified against the active kernel nodes public key
func VerifyKernelTransaction(rpc string, out *mtg.Action, timeout time.Duration) error {
	hash, err := crypto.HashFromString(out.TransactionHash)
	if err != nil {
		return err
	}
	signed, err := ReadKernelTransaction(rpc, hash)
	logger.Printf("common.readKernelTransaction(%s) => %v %v", out.TransactionHash, signed, err)

	if (err != nil || signed == nil) && out.CreatedAt.Add(timeout).After(time.Now()) {
		time.Sleep(5 * time.Second)
		return VerifyKernelTransaction(rpc, out, timeout)
	} else if err != nil || signed == nil {
		return fmt.Errorf("common.VerifyKernelTransaction(%v) not found %v", out, err)
	}

	if !strings.Contains(string(signed.Extra), out.Extra) && !strings.Contains(hex.EncodeToString(signed.Extra), out.Extra) {
		return fmt.Errorf("common.VerifyKernelTransaction(%v) memo mismatch %x", out, signed.Extra)
	}
	if signed.Asset != crypto.Sha256Hash([]byte(out.AssetId)) {
		return fmt.Errorf("common.VerifyKernelTransaction(%v) asset mismatch %s", out, signed.Asset)
	}
	if len(signed.Outputs) < out.OutputIndex+1 {
		return fmt.Errorf("common.VerifyKernelTransaction(%v) output mismatch %d", out, len(signed.Outputs))
	}
	if a, _ := decimal.NewFromString(signed.Outputs[out.OutputIndex].Amount.String()); !a.Equal(out.Amount) {
		return fmt.Errorf("common.VerifyKernelTransaction(%v) amount mismatch %s", out, a)
	}

	return nil
}

func DecodeMixinObjectExtra(extra []byte) []byte {
	_, _, m := mtg.DecodeMixinExtra(hex.EncodeToString(extra))
	b, _ := base64.RawURLEncoding.DecodeString(m)
	return b
}

func CreateObjectUntilSufficient(ctx context.Context, memo, traceId string, uid, sid, priv, pin, pinToken string) (*bot.Snapshot, error) {
	fee := bot.EstimateObjectFee(memo)
	in := &bot.ObjectInput{
		TraceId: traceId,
		Amount:  fee,
		Memo:    memo,
	}
	for {
		rs, err := bot.CreateObject(ctx, in, uid, sid, priv, pin, pinToken)
		logger.Printf("bot.CreateObject(%v) => %v %v", in, rs, err)
		if mixin.IsErrorCodes(err, 30103) {
			time.Sleep(7 * time.Second)
			continue
		}
		if err != nil && CheckRetryableError(err) {
			time.Sleep(7 * time.Second)
			continue
		}
		return rs, err
	}
}

func SendTransactionUntilSufficient(ctx context.Context, client *mixin.Client, assetId string, receivers []string, threshold int, amount decimal.Decimal, memo, traceId, sessionPrivateKey string) error {
	for {
		err := SendTransaction(ctx, client, assetId, receivers, threshold, amount, memo, traceId, sessionPrivateKey)
		if mixin.IsErrorCodes(err, 30103) {
			time.Sleep(7 * time.Second)
			continue
		}
		if err != nil && CheckRetryableError(err) {
			time.Sleep(7 * time.Second)
			continue
		}
		return err
	}
}

func SendTransaction(ctx context.Context, client *mixin.Client, assetId string, receivers []string, threshold int, amount decimal.Decimal, memo, traceId, sessionPrivateKey string) error {
	logger.Printf("SendTransaction(%s, %v, %d, %s, %s, %s)", assetId, receivers, threshold, amount, memo, traceId)
	input := &mixin.TransferInput{
		AssetID: assetId,
		Amount:  amount,
		TraceID: traceId,
		Memo:    memo,
	}
	if len(receivers) == 1 {
		input.OpponentID = receivers[0]
		_, err := client.Transfer(ctx, input, pin)
		return err
	}
	input.OpponentMultisig.Receivers = receivers
	input.OpponentMultisig.Threshold = uint8(threshold)
	_, err := client.Transaction(ctx, input, pin)
	return err
}

func ReadKernelTransaction(rpc string, tx crypto.Hash) (*common.VersionedTransaction, error) {
	raw, err := callMixinRPC(rpc, "gettransaction", []any{tx.String()})
	if err != nil || raw == nil {
		return nil, err
	}
	var signed map[string]any
	err = json.Unmarshal(raw, &signed)
	if err != nil {
		return nil, err
	}
	if signed["hex"] == nil {
		return nil, fmt.Errorf("transaction %s not found in kernel", tx)
	}
	hex, err := hex.DecodeString(signed["hex"].(string))
	if err != nil {
		return nil, err
	}
	return common.UnmarshalVersionedTransaction(hex)
}

func callMixinRPC(node, method string, params []any) ([]byte, error) {
	client := &http.Client{Timeout: 20 * time.Second}

	body := MarshalJSONOrPanic(map[string]any{
		"method": method,
		"params": params,
	})
	req, err := http.NewRequest("POST", node, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data  any `json:"data"`
		Error any `json:"error"`
	}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	err = dec.Decode(&result)
	if err != nil {
		return nil, err
	}
	if result.Error != nil {
		return nil, fmt.Errorf("ERROR %s", result.Error)
	}
	if result.Data == nil {
		return nil, nil
	}

	return json.Marshal(result.Data)
}
