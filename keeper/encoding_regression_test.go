package keeper

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestDepositExtraRequiresCompleteChainHeader(t *testing.T) {
	for _, tc := range []struct {
		chain, curve byte
		size         int
	}{
		{common.SafeChainBitcoin, common.CurveSecp256k1ECDSABitcoin, 57},
		{common.SafeChainLitecoin, common.CurveSecp256k1ECDSALitecoin, 57},
		{common.SafeChainEthereum, common.CurveSecp256k1ECDSAEthereum, 77},
		{common.SafeChainPolygon, common.CurveSecp256k1ECDSAPolygon, 77},
	} {
		t.Run(fmt.Sprint(tc.chain), func(t *testing.T) {
			extra := make([]byte, tc.size+1)
			extra[0] = tc.chain
			extra[tc.size] = 42
			for n := 0; n < tc.size; n++ {
				_, err := parseDepositExtra(&common.Request{Curve: tc.curve, ExtraHEX: hex.EncodeToString(extra[:n])})
				require.Error(t, err, "length %d", n)
			}
			deposit, err := parseDepositExtra(&common.Request{Curve: tc.curve, ExtraHEX: hex.EncodeToString(extra)})
			require.NoError(t, err)
			require.Equal(t, int64(42), deposit.Amount.Int64())
		})
	}
}

func TestInheritanceExtraPreservesNetworkInfoID(t *testing.T) {
	ctx := context.Background()
	db, err := OpenSQLite3Store(filepath.Join(t.TempDir(), "safe.sqlite3"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	node := &Node{store: db}
	req := &common.Request{Id: uuid.Must(uuid.NewV4()).String(), CreatedAt: time.Now()}
	safe := &store.Safe{Holder: "holder", Chain: common.SafeChainBitcoin}
	networkID := uuid.Must(uuid.NewV4()).Bytes()
	extra := make([]byte, 34)
	binary.BigEndian.PutUint16(extra[32:], 24*400)
	extra = append(extra, networkID...)
	for n := 0; n < len(extra); n++ {
		_, _, err := node.processSafeInheritanceLock(ctx, req, safe, common.FlagProposeSetInheritance, extra[:n])
		require.Error(t, err, "set inheritance length %d", n)
	}
	lock, suffix, err := node.processSafeInheritanceLock(ctx, req, safe, common.FlagProposeSetInheritance, extra)
	require.NoError(t, err)
	require.NotNil(t, lock)
	require.Equal(t, networkID, suffix)
	// Removal has a 16-byte lock ID followed by the same network-info ID.
	for n := 0; n < 32; n++ {
		_, _, err := node.processSafeInheritanceLock(ctx, req, safe, common.FlagProposeRemoveInheritance, make([]byte, n))
		require.ErrorContains(t, err, "invalid lock extra", "remove inheritance length %d", n)
	}
}
