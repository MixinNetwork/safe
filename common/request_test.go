package common

import (
	"context"
	"testing"
	"time"

	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/stretchr/testify/require"
)

func TestRequest(t *testing.T) {
	require := require.New(t)
	var client *mixin.Client
	ctx := context.Background()
	ctx = EnableTestEnvironment(ctx)

	req := &Request{Action: ActionBitcoinSafeProposeAccount}
	extra := "00010101e459de8b4edd44ffa119b1d707f8521a"
	arp, err := req.ParseMixinRecipient(ctx, client, DecodeHexOrPanic(extra))
	require.Nil(err)
	require.NotNil(arp)
	require.Equal([]string{"e459de8b-4edd-44ff-a119-b1d707f8521a"}, arp.Receivers)
	require.Equal(byte(1), arp.Threshold)
	require.Equal(time.Hour, arp.Timelock)
	require.Equal("", arp.Observer)

	extra = "00010101e459de8b4edd44ffa119b1d707f8521a039c2f5ebdd4eae6d69e7a98b737beeb78e0a8d42c7b957a0fbe0c41658d16ab40"
	arp, err = req.ParseMixinRecipient(ctx, client, DecodeHexOrPanic(extra))
	require.Nil(err)
	require.NotNil(arp)
	require.Equal([]string{"e459de8b-4edd-44ff-a119-b1d707f8521a"}, arp.Receivers)
	require.Equal(byte(1), arp.Threshold)
	require.Equal(time.Hour, arp.Timelock)
	require.Equal("039c2f5ebdd4eae6d69e7a98b737beeb78e0a8d42c7b957a0fbe0c41658d16ab40", arp.Observer)
}
