package mixinwallet

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
	"github.com/shopspring/decimal"
)

type MixinWallet struct {
	client *mixin.Client
	store  *SQLite3Store
	epoch  uint64
}

func (mw *MixinWallet) drainOutputsFromNetwork(ctx context.Context) {
	for {
		checkpoint, err := mw.readDrainCheckpoint(ctx)
		if err != nil {
			panic(err)
		}
		utxos, err := common.SafeListUtxos(ctx, mw.client, nil, 1, "", checkpoint, mixin.SafeUtxoStateUnspent)
		if err != nil {
			panic(err)
		}
		err = mw.writeOutputsIfNotExists(ctx, utxos)
		if err != nil {
			panic(err)
		}
		err = mw.writeDrainCheckpoint(ctx, utxos[len(utxos)-1].Sequence+1)
		if err != nil {
			panic(err)
		}

		interval := time.Second * 3
		if len(utxos) == 500 {
			interval = time.Second * 1
		}
		time.Sleep(interval)
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
