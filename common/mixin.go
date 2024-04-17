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
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
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
	if err != nil {
		return err
	}
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

func SendTransactionUntilSufficient(ctx context.Context, client *mixin.Client, members []string, threshold int, receivers []string, receiversThreshold int, amount decimal.Decimal, traceId, assetId, memo, spendPrivateKey string) (*mixin.SafeTransactionRequest, error) {
	utxos, err := listSafeUtxosUntilSufficient(ctx, client, members, threshold, assetId)
	if err != nil {
		return nil, err
	}
	b := mixin.NewSafeTransactionBuilder(utxos)
	b.Memo = memo
	b.Hint = traceId

	tx, err := client.MakeTransaction(ctx, b, []*mixin.TransactionOutput{
		{
			Address: mixin.RequireNewMixAddress(receivers, byte(receiversThreshold)),
			Amount:  amount,
		},
	})
	if err != nil {
		return nil, err
	}
	raw, err := tx.Dump()
	if err != nil {
		return nil, err
	}
	req, err := createSafeTransactionRequest(ctx, client, traceId, raw)
	if err != nil {
		return nil, err
	}
	_, err = signMultisigUntilSufficient(ctx, client, req, members, spendPrivateKey)
	return req, err
}

func listSafeUtxosUntilSufficient(ctx context.Context, client *mixin.Client, members []string, threshold int, assetId string) ([]*mixin.SafeUtxo, error) {
	for {
		utxos, err := client.SafeListUtxos(ctx, mixin.SafeListUtxoOption{
			Members:   members,
			Threshold: uint8(threshold),
			State:     mixin.SafeUtxoStateUnspent,
			Asset:     assetId,
		})
		logger.Verbosef("mixin.SafeListUtxos(%v %d %s) => %v %v\n", members, threshold, assetId, utxos, err)
		if err != nil && CheckRetryableError(err) {
			time.Sleep(3 * time.Second)
			continue
		}
		return utxos, err
	}
}

func createSafeTransactionRequest(ctx context.Context, client *mixin.Client, id, raw string) (*mixin.SafeTransactionRequest, error) {
	for {
		req, err := client.SafeCreateTransactionRequest(ctx, &mixin.SafeTransactionRequestInput{
			RequestID:      id,
			RawTransaction: raw,
		})
		logger.Verbosef("mixin.SafeCreateTransactionRequest(%s, %s) => %v %v\n", id, raw, req, err)
		if err != nil && CheckRetryableError(err) {
			time.Sleep(3 * time.Second)
			continue
		}
		return req, err
	}
}

func signMultisigUntilSufficient(ctx context.Context, client *mixin.Client, input *mixin.SafeTransactionRequest, members []string, spendPrivateKey string) (*mixin.SafeTransactionRequest, error) {
	key, err := mixinnet.KeyFromString(spendPrivateKey)
	if err != nil {
		return nil, err
	}
	index := -1
	for i, id := range members {
		if id == client.ClientID {
			index = i
		}
	}
	if index == -1 {
		return nil, fmt.Errorf("invalid signer index: %d", index)
	}

	ver, err := mixinnet.TransactionFromRaw(input.RawTransaction)
	if err != nil {
		return nil, err
	}
	err = mixin.SafeSignTransaction(ver, key, input.Views, uint16(index))
	if err != nil {
		return nil, err
	}
	signedRaw, err := ver.Dump()
	if err != nil {
		return nil, err
	}
	for {
		req, err := client.SafeSubmitTransactionRequest(ctx, &mixin.SafeTransactionRequestInput{
			RequestID:      input.RequestID,
			RawTransaction: signedRaw,
		})
		logger.Verbosef("group.SafeSignMultisigRequest(%s %s) => %v %v\n", input.RequestID, signedRaw, req, err)
		if err != nil && CheckRetryableError(err) {
			time.Sleep(3 * time.Second)
			continue
		}
		return req, err
	}
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
