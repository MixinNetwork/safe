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

var sequence = 0

func TestWallet(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	ctx = EnableTestEnvironment(ctx)

	root, err := os.MkdirTemp("", "wallet-test")
	db, err := OpenWalletSQLite3Store(root + "/wallet.sqlite3")
	require.Nil(err)
	mw := &MixinWallet{
		epoch: 0,
		store: db,
		client: &mixin.Client{
			ClientID: "bot-id",
		},
	}

	var os []*mixin.SafeUtxo
	for range 4 {
		o := buildOutput(mtg.StorageAssetId, "0.2")
		os = append(os, o)
	}
	for range 4 {
		o := buildOutput(mtg.StorageAssetId, "0.1")
		os = append(os, o)
	}
	for range 4 {
		o := buildOutput(SafeSolanaChainId, "0.1")
		os = append(os, o)
	}
	err = mw.writeOutputsIfNotExists(ctx, os)
	require.Nil(err)

	id := uuid.Must(uuid.NewV4()).String()
	os1, err := mw.LockUTXOs(ctx, id, mtg.StorageAssetId, decimal.RequireFromString("0.5"))
	require.Nil(err)
	require.Len(os1, 3)
	os2, err := mw.LockUTXOs(ctx, id, mtg.StorageAssetId, decimal.RequireFromString("0.5"))
	require.Nil(err)
	require.Len(os2, 3)
	for i, o1 := range os1 {
		o2 := os2[i]
		require.Equal(o1.OutputID, o2.OutputID)
		require.Equal("0.2", o1.Amount.String())
		require.Equal("0.2", o2.Amount.String())

		require.Equal(OutputStateUnspent, o1.State)
		require.Equal(OutputStateLocked, o2.State)
	}

	id = uuid.Must(uuid.NewV4()).String()
	os, err = mw.LockUTXOs(ctx, id, mtg.StorageAssetId, decimal.RequireFromString("0.5"))
	require.Nil(err)
	require.Len(os, 4)

	id = uuid.Must(uuid.NewV4()).String()
	os, err = mw.LockUTXOs(ctx, id, mtg.StorageAssetId, decimal.RequireFromString("0.2"))
	require.NotNil(err)
	require.True(strings.Contains(err.Error(), "insufficient outputs"))
}

func buildOutput(assetId string, amount string) *mixin.SafeUtxo {
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
		Sequence:        uint64(sequence),
	}
	sequence += 2
	return o
}
