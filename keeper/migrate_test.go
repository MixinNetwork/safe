package keeper

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
	gc "github.com/ethereum/go-ethereum/common"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

const (
	testObserverDepositEntry = "0x9d04735aaEB73535672200950fA77C2dFC86eB21"
	testSafeBondId           = "728ed44b-a751-3b49-81e0-003815c8184c"
)

func TestKeeperMigration(t *testing.T) {
	require := require.New(t)
	ctx, node, _, _ := testPrepare(require)

	id := uuid.Must(uuid.NewV4()).String()
	holder := testPublicKey(testBitcoinKeyHolderPrivate)
	out := testBuildObserverMigrateRequest(node, id, holder, common.ActionMigrateSafeToken, gc.HexToAddress(testObserverDepositEntry).Bytes(), common.CurveSecp256k1ECDSABitcoin)
	testStep(ctx, require, node, out)

	safe, err := node.store.ReadSafe(ctx, holder)
	require.Nil(err)
	require.Equal(testObserverDepositEntry, safe.Receiver)
}

func testBuildObserverMigrateRequest(node *Node, id, public string, action byte, extra []byte, crv byte) *mtg.Action {
	op := &common.Operation{
		Id:     id,
		Type:   action,
		Curve:  crv,
		Public: public,
		Extra:  extra,
	}
	memo := mtg.EncodeMixinExtra(uuid.Must(uuid.NewV4()).String(), uuid.Must(uuid.NewV4()).String(), string(op.Encode()))
	memo = hex.EncodeToString([]byte(memo))
	timestamp := time.Now()
	if action == common.ActionObserverAddKey {
		timestamp = timestamp.Add(-SafeKeyBackupMaturity)
	}
	return &mtg.Action{
		Senders:         node.conf.ObserverUserId,
		AssetId:         testSafeBondId,
		Extra:           memo,
		TransactionHash: crypto.Sha256Hash([]byte(op.Id)).String(),
		Amount:          decimal.New(1, 1),
		CreatedAt:       timestamp,
		UpdatedAt:       timestamp,
		Sequence:        sequence,
	}
}
