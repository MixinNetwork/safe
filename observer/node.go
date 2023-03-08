package observer

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid"
	"github.com/shopspring/decimal"
)

const (
	snapshotsCheckpointKey = "snapshots-checkpoint"
)

type Node struct {
	conf        *Configuration
	aesKey      [32]byte
	keeper      *mtg.Configuration
	mixin       *mixin.Client
	keeperStore *store.SQLite3Store
	store       *SQLite3Store
}

func NewNode(db *SQLite3Store, kd *store.SQLite3Store, conf *Configuration, keeper *mtg.Configuration, mixin *mixin.Client) *Node {
	node := &Node{
		conf:        conf,
		keeper:      keeper,
		store:       db,
		keeperStore: kd,
		mixin:       mixin,
	}
	node.aesKey = common.ECDHEd25519(conf.PrivateKey, conf.KeeperPublicKey)
	return node
}

func (node *Node) Boot(ctx context.Context) {
	err := node.sendBitcoinPriceInfo(ctx)
	if err != nil {
		panic(err)
	}
	go node.bitcoinNetworkInfoLoop(ctx)
	go node.bitcoinRPCBlocksLoop(ctx)
	go node.bitcoinDepositConfirmLoop(ctx)
	go node.bitcoinTransactionApprovalLoop(ctx)
	go node.bitcoinKeyLoop(ctx)
	node.snapshotsLoop(ctx)
}

func (node *Node) sendBitcoinPriceInfo(ctx context.Context) error {
	asset, err := node.fetchAssetMeta(ctx, node.conf.PriceAssetId)
	if err != nil {
		return err
	}
	amount := decimal.RequireFromString(node.conf.PriceAmount)
	logger.Printf("node.sendBitcoinPriceInfo(%s, %s)", asset.AssetId, amount)
	amount = amount.Mul(decimal.New(1, 8))
	if amount.Sign() <= 0 || !amount.IsInteger() || !amount.BigInt().IsInt64() {
		panic(node.conf.PriceAmount)
	}
	dummy := node.bitcoinDummyHolder()
	id := mixin.UniqueConversationID(asset.AssetId, amount.String())
	id = mixin.UniqueConversationID(id, keeper.SafeBitcoinChainId)
	extra := []byte{keeper.SafeChainBitcoin}
	extra = append(extra, uuid.Must(uuid.FromString(asset.AssetId)).Bytes()...)
	extra = binary.BigEndian.AppendUint64(extra, uint64(amount.IntPart()))
	return node.sendBitcoinKeeperResponse(ctx, dummy, common.ActionObserverSetPrice, id, extra)
}

func (node *Node) snapshotsLoop(ctx context.Context) {
	for {
		offset, err := node.readSnapshotsCheckpoint(ctx)
		if err != nil {
			panic(err)
		}
		var snapshots []*mixin.Snapshot
		err = node.mixin.Get(ctx, "/snapshots", map[string]string{
			"limit":  "500",
			"order":  "ASC",
			"offset": offset.Format(time.RFC3339Nano),
		}, &snapshots)
		if err != nil {
			logger.Printf("mixin.GetSnapshots(%s) => %v", offset, err)
			time.Sleep(1 * time.Second)
			continue
		}

		for _, s := range snapshots {
			err := node.handleSnapshot(ctx, s)
			if err != nil {
				panic(err)
			}
			offset = s.CreatedAt
		}

		err = node.writeSnapshotsCheckpoint(ctx, offset)
		if err != nil {
			panic(err)
		}
		if len(snapshots) < 500 {
			time.Sleep(1 * time.Second)
		}
	}
}

func (node *Node) handleSnapshot(ctx context.Context, s *mixin.Snapshot) error {
	logger.Verbosef("node.handleSnapshot(%v)", s)
	if s.Amount.Sign() < 0 {
		return nil
	}
	handled, err := node.handleBondAsset(ctx, s)
	if err != nil || handled {
		return err
	}

	msp := mtg.DecodeMixinExtra(s.Memo)
	if msp == nil {
		return nil
	}
	b := common.AESDecrypt(node.aesKey[:], []byte(msp.M))
	op, err := common.DecodeOperation(b)
	logger.Printf("common.DecodeOperation(%x) => %v %v", b, op, err)
	if err != nil {
		return nil
	}
	data, err := common.MVMStorageRead(node.conf.MVMRPC, op.Extra)
	if err != nil || len(data) < 32 {
		panic(hex.EncodeToString([]byte(s.Memo)))
	}

	switch op.Type {
	case common.ActionBitcoinSafeProposeTransaction:
		return node.saveTransactionProposal(ctx, data, s.CreatedAt)
	case common.ActionBitcoinSafeApproveTransaction:
		return node.bitcoinAccountantSignTransaction(ctx, data)
	case common.ActionBitcoinSafeProposeAccount:
		return node.saveAccountProposal(ctx, data, s.CreatedAt)
	case common.ActionBitcoinSafeApproveAccount:
		return node.deployBitcoinSafeBond(ctx, data)
	}

	return nil
}

func (node *Node) handleBondAsset(ctx context.Context, s *mixin.Snapshot) (bool, error) {
	meta, err := node.fetchAssetMeta(ctx, s.AssetID)
	if err != nil {
		return false, fmt.Errorf("node.fetchAssetMeta(%s) => %v", s.AssetID, err)
	}
	if meta.Chain != keeper.SafeChainMVM {
		return false, nil
	}
	deployed, err := abi.CheckFactoryAssetDeployed(node.conf.MVMRPC, meta.AssetKey)
	logger.Verbosef("abi.CheckFactoryAssetDeployed(%s) => %v %v", meta.AssetKey, deployed, err)
	if err != nil {
		return false, fmt.Errorf("abi.CheckFactoryAssetDeployed(%s) => %v", meta.AssetKey, err)
	}
	if deployed.Sign() <= 0 {
		return false, nil
	}

	receivers := node.keeper.Genesis.Members
	threshold := node.keeper.Genesis.Threshold
	traceId := node.safeTraceId(s.SnapshotID, "BOND")
	return true, common.SendTransactionUntilSufficient(ctx, node.mixin, s.AssetID, receivers, threshold, s.Amount, "", traceId, node.conf.App.PIN)
}

func (node *Node) readSnapshotsCheckpoint(ctx context.Context) (time.Time, error) {
	val, err := node.store.ReadProperty(ctx, snapshotsCheckpointKey)
	if err != nil || val == "" {
		return time.Unix(0, node.conf.Timestamp), err
	}
	return time.Parse(time.RFC3339Nano, val)
}

func (node *Node) writeSnapshotsCheckpoint(ctx context.Context, offset time.Time) error {
	return node.store.WriteProperty(ctx, snapshotsCheckpointKey, offset.Format(time.RFC3339Nano))
}

func (node *Node) safeTraceId(params ...string) string {
	traceId := mixin.UniqueConversationID(node.conf.PrivateKey, node.conf.PrivateKey)
	for _, id := range params {
		traceId = mixin.UniqueConversationID(traceId, id)
	}
	return traceId
}
