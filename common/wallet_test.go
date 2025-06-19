package common

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/MixinNetwork/safe/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

func TestWallet(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	ctx = EnableTestEnvironment(ctx)

	root, err := os.MkdirTemp("", "wallet-test")
	require.Nil(err)
	db, err := OpenWalletSQLite3Store(root + "/wallet.sqlite3")
	require.Nil(err)
	mw := &MixinWallet{
		epoch: 0,
		store: db,
		client: &mixin.Client{
			ClientID: "bot-id",
		},
	}

	var sequence uint64
	var os []*mixin.SafeUtxo
	for range 4 {
		sequence = sequence + 2
		o := buildOutput(mtg.StorageAssetId, "0.2", sequence)
		os = append(os, o)
	}
	for range 4 {
		sequence = sequence + 2
		o := buildOutput(mtg.StorageAssetId, "0.1", sequence)
		os = append(os, o)
	}
	for range 4 {
		sequence = sequence + 2
		o := buildOutput(SafeSolanaChainId, "0.1", sequence)
		os = append(os, o)
	}
	err = mw.writeOutputsIfNotExists(ctx, os)
	require.Nil(err)
	outputs, total, err := mw.store.ListUnspentUTXOsByAsset(ctx, mtg.StorageAssetId)
	require.Nil(err)
	require.Len(outputs, 8)
	require.Equal("1.2", total.String())
	outputs, total, err = mw.store.ListUnspentUTXOsByAsset(ctx, SafeSolanaChainId)
	require.Nil(err)
	require.Len(outputs, 4)
	require.Equal("0.4", total.String())

	id := uuid.Must(uuid.NewV4()).String()
	os1, err := mw.LockUTXOs(ctx, id, mtg.StorageAssetId, decimal.RequireFromString("0.5"))
	require.Nil(err)
	require.Len(os1, 3)
	outputs, total, err = mw.store.ListUnspentUTXOsByAsset(ctx, mtg.StorageAssetId)
	require.Nil(err)
	require.Len(outputs, 5)
	require.Equal("0.6", total.String())

	os2, err := mw.LockUTXOs(ctx, id, mtg.StorageAssetId, decimal.RequireFromString("0.5"))
	require.Nil(err)
	require.Len(os2, 3)
	outputs, total, err = mw.store.ListUnspentUTXOsByAsset(ctx, mtg.StorageAssetId)
	require.Nil(err)
	require.Len(outputs, 5)
	require.Equal("0.6", total.String())
	for i, o1 := range os1 {
		o2 := os2[i]
		require.Equal(o1.OutputID, o2.OutputID)
		require.Equal("0.2", o1.Amount.String())
		require.Equal("0.2", o2.Amount.String())

		require.Equal(OutputStateLocked, string(o1.State))
		require.Equal(OutputStateLocked, string(o2.State))
	}

	id = uuid.Must(uuid.NewV4()).String()
	os, err = mw.LockUTXOs(ctx, id, mtg.StorageAssetId, decimal.RequireFromString("0.5"))
	require.Nil(err)
	require.Len(os, 4)
	outputs, total, err = mw.store.ListUnspentUTXOsByAsset(ctx, mtg.StorageAssetId)
	require.Nil(err)
	require.Len(outputs, 1)
	require.Equal("0.1", total.String())

	id = uuid.Must(uuid.NewV4()).String()
	os, err = mw.LockUTXOs(ctx, id, mtg.StorageAssetId, decimal.RequireFromString("0.2"))
	require.NotNil(err)
	require.True(strings.Contains(err.Error(), "insufficient outputs"))
	require.Len(os, 0)
	outputs, total, err = mw.store.ListUnspentUTXOsByAsset(ctx, mtg.StorageAssetId)
	require.Nil(err)
	require.Len(outputs, 1)
	require.Equal("0.1", total.String())
}

func buildOutput(assetId, amount string, sequence uint64) *mixin.SafeUtxo {
	id := UniqueId(assetId, amount)
	id = UniqueId(id, fmt.Sprintf("%d", sequence))
	hash := mixinnet.NewHash([]byte(id))
	amt := decimal.RequireFromString(amount)

	o := &mixin.SafeUtxo{
		OutputID:        id,
		TransactionHash: hash,
		OutputIndex:     0,
		AssetID:         assetId,
		Amount:          amt,
		State:           OutputStateUnspent,
		Sequence:        sequence,
	}
	return o
}
