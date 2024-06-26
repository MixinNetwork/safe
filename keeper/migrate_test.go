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
	testSafeBondId           = "728ed44b-a751-3b49-81e0-003815c8184c"
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
			CreatedAt: time.Now(),
		},
	})
	testEthereumObserverHolderDeposit(ctx, require, node, mpc, observer, "ca6324635b0c87409e9d8488e7f6bcc1fd8224c276a3788b1a8c56ddb4e20f07", SafePolygonChainId, ethereum.EthereumEmptyAddress, "100000000000000")

	safe, err := node.store.ReadSafe(ctx, holder)
	require.Nil(err)
	bs, err := node.store.ReadEthereumAllBalance(ctx, safe.Address)
	require.Nil(err)
	require.True(len(bs) > 0)
	for _, b := range bs {
		require.Equal(false, b.Migrated)
	}

	id := uuid.Must(uuid.NewV4()).String()
	out := testBuildObserverMigrateRequest(node, id, holder, common.ActionMigrateSafeToken, gc.HexToAddress(testObserverDepositEntry).Bytes(), common.CurveSecp256k1ECDSAEthereum)
	testStep(ctx, require, node, out)

	safe, err = node.store.ReadSafe(ctx, holder)
	require.Nil(err)
	require.Equal(testObserverDepositEntry, safe.Receiver)

	bs, err = node.store.ReadEthereumAllBalance(ctx, safe.Address)
	require.Nil(err)
	require.True(len(bs) > 0)
	for _, b := range bs {
		require.Equal(true, b.Migrated)
	}

	cnbAssetId := ethereum.GenerateAssetId(SafeChainPolygon, testEthereumUSDTAddress)
	require.Equal(testEthereumUSDTAssetId, cnbAssetId)
	cnbBondId := testDeployBondContract(ctx, require, node, testEthereumSafeAddress, cnbAssetId)
	require.Equal(testEthereumUSDTBondAssetId, cnbBondId)
	node.ProcessOutput(ctx, &mtg.Action{
		UnifiedOutput: mtg.UnifiedOutput{
			AssetId:   cnbBondId,
			Amount:    decimal.NewFromInt(100),
			CreatedAt: time.Now(),
		},
	})
	testEthereumObserverHolderDeposit(ctx, require, node, mpc, observer, "55523d5ca29884f93dfa1c982177555ac5e13be49df10017054cb71aaba96595", cnbAssetId, testEthereumUSDTAddress, "100")

	b, err := node.store.ReadEthereumBalance(ctx, safe.Address, cnbAssetId)
	require.Nil(err)
	require.Equal(false, b.Migrated)
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
		TransactionHash: crypto.Sha256Hash([]byte(op.Id)).String(),
		UnifiedOutput: mtg.UnifiedOutput{
			Senders:   []string{node.conf.ObserverUserId},
			AssetId:   testSafeBondId,
			Extra:     memo,
			Amount:    decimal.New(1, 1),
			CreatedAt: timestamp,
			UpdatedAt: timestamp,
			Sequence:  sequence,
		},
	}
}
