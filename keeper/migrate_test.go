package keeper

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
	gc "github.com/ethereum/go-ethereum/common"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

const (
	testObserverDepositEntry = "0x9d04735aaEB73535672200950fA77C2dFC86eB21"
)

func TestKeeperMigration(t *testing.T) {
	require := require.New(t)
	ctx, node, mpc, _ := testEthereumPrepare(require)

	holder := testPublicKey(testEthereumKeyHolder)
	observer := testEthereumPublicKey(testEthereumKeyObserver)

	node.ProcessOutput(ctx, &mtg.Action{
		UnifiedOutput: mtg.UnifiedOutput{
			AssetId:   testEthereumBondAssetId,
			Amount:    decimal.NewFromInt(100000000000000),
			Extra:     testGenerateDummyExtra(node),
			CreatedAt: time.Now(),
		},
	})
	testEthereumObserverHolderDeposit(ctx, require, node, mpc, observer, "ca6324635b0c87409e9d8488e7f6bcc1fd8224c276a3788b1a8c56ddb4e20f07", common.SafePolygonChainId, ethereum.EthereumEmptyAddress, "100000000000000")

	err := node.Migrate(ctx)
	require.Nil(err)

	id := uuid.Must(uuid.NewV4()).String()
	asset := node.getBondAssetId(ctx, node.conf.PolygonObserverDepositEntry, common.SafePolygonChainId, holder)
	out := testBuildObserverMigrateRequest(node, id, holder, common.ActionMigrateSafeToken, gc.HexToAddress(testObserverDepositEntry).Bytes(), common.CurveSecp256k1ECDSAEthereum, asset)
	testStep(ctx, require, node, out)

	safe, err := node.store.ReadSafe(ctx, holder)
	require.Nil(err)
	require.Equal(asset, safe.SafeAssetId)
}

func testBuildObserverMigrateRequest(node *Node, id, public string, action byte, extra []byte, crv byte, asset string) *mtg.Action {
	op := &common.Operation{
		Id:     id,
		Type:   action,
		Curve:  crv,
		Public: public,
		Extra:  extra,
	}
	memo := mtg.EncodeMixinExtraBase64(node.conf.AppId, op.Encode())
	memo = hex.EncodeToString([]byte(memo))
	timestamp := time.Now()
	if action == common.ActionObserverAddKey {
		timestamp = timestamp.Add(-SafeKeyBackupMaturity)
	}
	return &mtg.Action{
		TransactionHash: crypto.Sha256Hash([]byte(op.Id)).String(),
		UnifiedOutput: mtg.UnifiedOutput{
			Senders:   []string{node.conf.ObserverUserId},
			AssetId:   asset,
			Extra:     memo,
			Amount:    decimal.New(1, 1),
			CreatedAt: timestamp,
			UpdatedAt: timestamp,
			Sequence:  sequence,
		},
	}
}
