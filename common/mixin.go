package common

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
	"github.com/shopspring/decimal"
)

func ExtraLimit(tx mixinnet.Transaction) int {
	if tx.Asset != mixinnet.XINAssetId {
		return common.ExtraSizeGeneralLimit
	}
	if len(tx.Outputs) < 1 {
		return common.ExtraSizeGeneralLimit
	}
	out := tx.Outputs[0]
	if len(out.Keys) != 1 {
		return common.ExtraSizeGeneralLimit
	}
	if out.Type != common.OutputTypeScript {
		return common.ExtraSizeGeneralLimit
	}
	if out.Script.String() != "fffe40" {
		return common.ExtraSizeGeneralLimit
	}
	step := mixinnet.IntegerFromString(common.ExtraStoragePriceStep)
	if out.Amount.Cmp(step) < 0 {
		return common.ExtraSizeGeneralLimit
	}
	cells := out.Amount.Count(step)
	limit := cells * common.ExtraSizeStorageStep
	if limit > common.ExtraSizeStorageCapacity {
		return common.ExtraSizeStorageCapacity
	}
	return int(limit)
}

func CreateObjectStorageUntilSufficient(ctx context.Context, mw *MixinWallet, client *mixin.Client, recipients []*bot.TransactionRecipient, extra []byte, sTraceId string, su bot.SafeUser) (crypto.Hash, error) {
	for {
		old, err := SafeReadTransactionRequestUntilSufficient(ctx, client, sTraceId)
		if err != nil {
			return crypto.Hash{}, err
		}
		if old != nil && old.State == mixin.SafeUtxoStateSpent {
			return crypto.HashFromString(old.TransactionHash)
		}
		if old != nil {
			time.Sleep(time.Second)
			continue
		}

		amount := bot.EstimateStorageCost(extra)
		utxos, err := mw.LockUTXOs(ctx, sTraceId, mtg.StorageAssetId, decimal.RequireFromString(amount.String()))
		if err != nil {
			return crypto.Hash{}, err
		}
		os := toBotOutput(utxos)

		_, err = bot.CreateObjectStorageTransaction(ctx, recipients, os, extra, sTraceId, nil, "", &su)
		logger.Verbosef("common.mixin.CreateObjectStorageTransaction(%s) => %v", sTraceId, err)
		if err == nil || CheckRetryableError(err) {
			time.Sleep(time.Second)
			continue
		}
		return crypto.Hash{}, err
	}
}

func SendTransactionUntilSufficient(ctx context.Context, mw *MixinWallet, client *mixin.Client, receivers []string, receiversThreshold int, amount decimal.Decimal, traceId, assetId, memo string, references []crypto.Hash, spendPrivateKey string) (*mixin.SafeTransactionRequest, error) {
	for {
		req, err := sendTransaction(ctx, mw, client, receivers, receiversThreshold, amount, traceId, assetId, memo, references, spendPrivateKey)
		if CheckRetryableError(err) {
			time.Sleep(time.Second)
			continue
		}
		if err != nil {
			return nil, err
		}
		if req.State == mixin.SafeUtxoStateSpent {
			return req, nil
		}
		time.Sleep(time.Second)
	}
}

func sendTransaction(ctx context.Context, mw *MixinWallet, client *mixin.Client, receivers []string, receiversThreshold int, amount decimal.Decimal, traceId, assetId, memo string, references []crypto.Hash, spendPrivateKey string) (*mixin.SafeTransactionRequest, error) {
	req, err := readTransaction(ctx, client, traceId)
	if err != nil || req != nil {
		return req, err
	}

	utxos, err := mw.LockUTXOs(ctx, traceId, assetId, amount)
	if err != nil {
		return nil, err
	}
	b := mixin.NewSafeTransactionBuilder(utxos)
	b.Memo = memo
	b.Hint = traceId

	tx, err := client.MakeTransaction(ctx, b, []*mixin.TransactionOutput{{
		Address: mixin.RequireNewMixAddress(receivers, byte(receiversThreshold)),
		Amount:  amount,
	}})
	if err != nil {
		return nil, err
	}
	tx.References = toMixinnetHash(references)
	raw, err := tx.Dump()
	if err != nil {
		return nil, err
	}
	req, err = createTransaction(ctx, client, traceId, raw)
	if err != nil {
		return nil, err
	}
	return signTransaction(ctx, client, req.RequestID, req.RawTransaction, req.Views, spendPrivateKey)
}

func listUnspentUTXOsUntilSufficient(ctx context.Context, client *mixin.Client, members []string, threshold uint8, assetId string, offset uint64) ([]*mixin.SafeUtxo, error) {
	for {
		utxos, err := client.SafeListUtxos(ctx, mixin.SafeListUtxoOption{
			Members:   members,
			Threshold: threshold,
			State:     mixin.SafeUtxoStateUnspent,
			Asset:     assetId,
			Offset:    offset,
		})
		logger.Verbosef("common.mixin.SafeListUtxos(%s, %s) => %d %v\n", client.ClientID, assetId, len(utxos), err)
		if CheckRetryableError(err) {
			time.Sleep(time.Second)
			continue
		}
		return utxos, err
	}
}

func createTransaction(ctx context.Context, client *mixin.Client, id, raw string) (*mixin.SafeTransactionRequest, error) {
	req, err := client.SafeCreateTransactionRequest(ctx, &mixin.SafeTransactionRequestInput{
		RequestID:      id,
		RawTransaction: raw,
	})
	logger.Verbosef("common.mixin.SafeCreateTransactionRequest(%s, %s) => %v %v\n", id, raw, req, err)
	return req, err
}

func signTransaction(ctx context.Context, client *mixin.Client, requestId, raw string, views []mixinnet.Key, spendPrivateKey string) (*mixin.SafeTransactionRequest, error) {
	key, err := mixinnet.KeyFromString(spendPrivateKey)
	if err != nil {
		return nil, err
	}
	ver, err := mixinnet.TransactionFromRaw(raw)
	if err != nil {
		return nil, err
	}
	err = mixin.SafeSignTransaction(ver, key, views, uint16(0))
	if err != nil {
		return nil, err
	}
	signedRaw, err := ver.Dump()
	if err != nil {
		return nil, err
	}
	req, err := client.SafeSubmitTransactionRequest(ctx, &mixin.SafeTransactionRequestInput{
		RequestID:      requestId,
		RawTransaction: signedRaw,
	})
	logger.Verbosef("common.mixin.SafeSubmitTransactionRequest(%s, %s) => %v %v\n", requestId, signedRaw, req, err)
	return req, err
}

func SafeReadTransactionRequestUntilSufficient(ctx context.Context, client *mixin.Client, id string) (*mixin.SafeTransactionRequest, error) {
	for {
		req, err := readTransaction(ctx, client, id)
		if CheckRetryableError(err) {
			time.Sleep(time.Second)
			continue
		}
		return req, err
	}
}

func readTransaction(ctx context.Context, client *mixin.Client, id string) (*mixin.SafeTransactionRequest, error) {
	req, err := client.SafeReadTransactionRequest(ctx, id)
	logger.Verbosef("common.mixin.SafeReadTransactionRequest(%s) => %v %v\n", id, req, err)
	if err == nil || mixin.IsErrorCodes(err, 404) {
		return req, nil
	}
	return nil, err
}

func SafeReadAssetUntilSufficient(ctx context.Context, id string) (*bot.AssetNetwork, error) {
	for {
		asset, err := bot.ReadAsset(ctx, id)
		logger.Verbosef("common.mixin.SafeReadAsset(%s) => %v %v", id, asset, err)
		if err == nil || mixin.IsErrorCodes(err, 404) {
			return asset, nil
		}
		if CheckRetryableError(err) {
			time.Sleep(time.Second)
			continue
		}
		return nil, err
	}
}

func SafeReadAssetsUntilSufficient(ctx context.Context, ids []string, su *bot.SafeUser) ([]*bot.Asset, error) {
	for {
		as, err := bot.FetchAssets(ctx, ids, su)
		logger.Verbosef("common.mixin.FetchAssets(%s) => %d %v", strings.Join(ids, ","), len(as), err)
		if err == nil {
			return as, nil
		}
		if CheckRetryableError(err) {
			time.Sleep(time.Second)
			continue
		}
		return nil, err
	}
}

func SafeReadWithdrawalFeeUntilSufficient(ctx context.Context, su *bot.SafeUser, assetId, feeAssetId, destination string) (*bot.AssetFee, error) {
	for {
		fees, err := bot.ReadAssetFee(ctx, assetId, destination, su)
		logger.Verbosef("common.mixin.ReadAssetFee(%s %s) => %v %v", assetId, destination, fees, err)
		if err == nil {
			for _, fee := range fees {
				if fee.AssetID == feeAssetId {
					return fee, nil
				}
			}
			return fees[0], nil
		}
		if CheckRetryableError(err) {
			time.Sleep(time.Second)
			continue
		}
		if mixin.IsErrorCodes(err, 404) {
			return nil, nil
		}
		return nil, err
	}
}

func SafeReadWithdrawalHashUntilSufficient(ctx context.Context, su *bot.SafeUser, id string) (string, error) {
	if CheckTestEnvironment(ctx) {
		return "jmHyRpKEuc1PgDjDaqaQqo9GpSM3pp9PhLgwzqpfa2uUbtRYJmbKtWp4onfNFsbk47paBjxz1d6s9n56Y8Na9Hp", nil
	}
	for {
		req, err := bot.GetTransactionByIdWithSafeUser(ctx, id, su)
		logger.Verbosef("bot.GetTransactionByIdWithSafeUser(%s) => %v %v", id, req, err)
		if err == nil {
			r := req.Receivers[0]
			if r.Destination == "" {
				return "", fmt.Errorf("invalid withdrawal tx: %s", id)
			}
			if r.WithdrawalHash == "" {
				return "", fmt.Errorf("withdrawal tx not confirmed: %s", id)
			}
			return r.WithdrawalHash, nil
		}
		if CheckRetryableError(err) {
			time.Sleep(time.Second)
			continue
		}
		if mixin.IsErrorCodes(err, 404) {
			return "", nil
		}
		return "", err
	}
}

func SafeAssetBalance(ctx context.Context, client *mixin.Client, members []string, threshold uint8, assetId string) (*common.Integer, int, error) {
	utxos, err := listUnspentUTXOsUntilSufficient(ctx, client, members, threshold, assetId, 0)
	if err != nil {
		return nil, 0, err
	}
	var total common.Integer
	for _, o := range utxos {
		amt := common.NewIntegerFromString(o.Amount.String())
		total = total.Add(amt)
	}
	return &total, len(utxos), nil
}

func ReadUsers(ctx context.Context, client *mixin.Client, ids []string) ([]*mixin.User, error) {
	if CheckTestEnvironment(ctx) {
		var us []*mixin.User
		for _, u := range ids {
			us = append(us, &mixin.User{
				UserID:  u,
				HasSafe: true,
			})
		}
		return us, nil
	}
	for {
		us, err := client.ReadUsers(ctx, ids...)
		logger.Verbosef("common.mixin.ReadUsers(%v) => %v %v\n", ids, us, err)
		if CheckRetryableError(err) {
			time.Sleep(time.Second)
			continue
		}
		return us, err
	}
}
