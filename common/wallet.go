package common

import (
	"context"
	_ "embed"
	"fmt"
	"strconv"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
	"github.com/shopspring/decimal"
)

type MixinWallet struct {
	client *mixin.Client
	store  *SQLite3Store
	epoch  uint64
}

func NewMixinWallet(client *mixin.Client, db *SQLite3Store, epoch uint64) *MixinWallet {
	return &MixinWallet{
		client: client,
		store:  db,
		epoch:  epoch,
	}
}

func (mw *MixinWallet) drainOutputsFromNetwork(ctx context.Context) {
	for {
		time.Sleep(time.Second)
		checkpoint, err := mw.readDrainCheckpoint(ctx)
		if err != nil {
			panic(err)
		}
		utxos, err := listUnspentUTXOsUntilSufficient(ctx, mw.client, "", checkpoint)
		if err != nil {
			panic(err)
		}
		if len(utxos) == 0 {
			continue
		}

		err = mw.writeOutputsIfNotExists(ctx, utxos)
		if err != nil {
			panic(err)
		}
		err = mw.writeDrainCheckpoint(ctx, utxos[len(utxos)-1].Sequence+1)
		if err != nil {
			panic(err)
		}
	}
}

func (mw *MixinWallet) Boot(ctx context.Context) {
	go mw.drainOutputsFromNetwork(ctx)
}

func (mw *MixinWallet) LockUTXOs(ctx context.Context, traceId, assetId string, amount decimal.Decimal) ([]*mixin.SafeUtxo, error) {
	os, err := mw.store.LockUTXOs(ctx, traceId, assetId, amount)
	if err != nil {
		return nil, err
	}
	var utxos []*mixin.SafeUtxo
	for _, o := range os {
		hash, err := mixinnet.HashFromString(o.TransactionHash)
		if err != nil {
			panic(err)
		}
		asset, err := mixinnet.HashFromString(o.KernelAssetId)
		if err != nil {
			panic(err)
		}

		utxos = append(utxos, &mixin.SafeUtxo{
			OutputID:           o.OutputId,
			TransactionHash:    hash,
			OutputIndex:        uint8(o.OutputIndex),
			KernelAssetID:      asset,
			AssetID:            o.AssetId,
			Amount:             o.Amount,
			SendersThreshold:   uint8(o.SendersThreshold),
			Senders:            o.Senders,
			ReceiversThreshold: 1,
			Receivers:          []string{mw.client.ClientID},
			State:              mixin.SafeUtxoState(o.State),
			Sequence:           o.Sequence,
			CreatedAt:          o.CreatedAt,
		})
	}
	return utxos, nil
}

func (mw *MixinWallet) writeOutputsIfNotExists(ctx context.Context, outputs []*mixin.SafeUtxo) error {
	return mw.store.WriteOutputsIfNotExists(ctx, outputs)
}

func (mw *MixinWallet) readDrainCheckpoint(ctx context.Context) (uint64, error) {
	ckt, err := mw.store.ReadProperty(ctx, OutputsDrainKey)
	if err != nil || ckt == "" {
		return mw.epoch, err
	}
	checkpoint, err := strconv.ParseUint(ckt, 10, 64)
	if err != nil {
		panic(ckt)
	}
	if checkpoint < mw.epoch {
		checkpoint = mw.epoch
	}
	return checkpoint, nil
}

func (mw *MixinWallet) writeDrainCheckpoint(ctx context.Context, offset uint64) error {
	return mw.store.WriteOrUpdateProperty(ctx, OutputsDrainKey, fmt.Sprintf("%d", offset))
}

func toBotOutput(utxos []*mixin.SafeUtxo) []*bot.Output {
	var outputs []*bot.Output
	for _, o := range utxos {
		outputs = append(outputs, &bot.Output{
			OutputID:        o.OutputID,
			TransactionHash: o.TransactionHash.String(),
			OutputIndex:     uint(o.OutputIndex),
			AssetId:         o.AssetID,
			KernelAssetId:   o.KernelAssetID.String(),
			Amount:          o.Amount.String(),
			State:           string(o.State),
			Sequence:        int64(o.Sequence),
		})
	}
	return outputs
}
