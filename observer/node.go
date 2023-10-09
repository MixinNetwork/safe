package observer

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid/v5"
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
	err := conf.Validate()
	if err != nil {
		panic(err)
	}
	node := &Node{
		conf:        conf,
		keeper:      keeper,
		store:       db,
		keeperStore: kd,
		mixin:       mixin,
	}
	node.aesKey = common.ECDHEd25519(conf.PrivateKey, conf.KeeperPublicKey)
	abi.InitFactoryContractAddress(conf.MVMFactoryAddress)
	return node
}

func (node *Node) Boot(ctx context.Context) {
	for _, chain := range []byte{
		keeper.SafeChainBitcoin,
		keeper.SafeChainLitecoin,
	} {
		err := node.sendBitcoinPriceInfo(ctx, chain)
		if err != nil {
			panic(err)
		}
		go node.bitcoinNetworkInfoLoop(ctx, chain)
		go node.bitcoinMixinWithdrawalsLoop(ctx, chain)
		go node.bitcoinRPCBlocksLoop(ctx, chain)
		go node.bitcoinDepositConfirmLoop(ctx, chain)
		go node.bitcoinTransactionApprovalLoop(ctx, chain)
		go node.bitcoinTransactionSpendLoop(ctx, chain)
	}
	go node.bitcoinKeyLoop(ctx)
	node.snapshotsLoop(ctx)
}

func (node *Node) sendBitcoinPriceInfo(ctx context.Context, chain byte) error {
	_, bitcoinAssetId := node.bitcoinParams(chain)
	asset, err := node.fetchAssetMeta(ctx, node.conf.OperationPriceAssetId)
	if err != nil {
		return err
	}
	amount := decimal.RequireFromString(node.conf.OperationPriceAmount)
	minimum := decimal.RequireFromString(node.conf.TransactionMinimum)
	logger.Printf("node.sendBitcoinPriceInfo(%d, %s, %s, %s)", chain, asset.AssetId, amount, minimum)
	amount = amount.Mul(decimal.New(1, 8))
	if amount.Sign() <= 0 || !amount.IsInteger() || !amount.BigInt().IsInt64() {
		panic(node.conf.OperationPriceAmount)
	}
	minimum = minimum.Mul(decimal.New(1, 8))
	if minimum.Sign() <= 0 || !minimum.IsInteger() || !minimum.BigInt().IsInt64() {
		panic(node.conf.TransactionMinimum)
	}
	if minimum.IntPart() < bitcoin.ValueDust(chain) {
		panic(node.conf.TransactionMinimum)
	}
	dummy := node.bitcoinDummyHolder()
	id := mixin.UniqueConversationID("ActionObserverSetOperationParams", dummy)
	id = mixin.UniqueConversationID(id, bitcoinAssetId)
	id = mixin.UniqueConversationID(id, asset.AssetId)
	id = mixin.UniqueConversationID(id, amount.String())
	id = mixin.UniqueConversationID(id, minimum.String())
	extra := []byte{chain}
	extra = append(extra, uuid.Must(uuid.FromString(asset.AssetId)).Bytes()...)
	extra = binary.BigEndian.AppendUint64(extra, uint64(amount.IntPart()))
	extra = binary.BigEndian.AppendUint64(extra, uint64(minimum.IntPart()))
	return node.sendBitcoinKeeperResponse(ctx, dummy, common.ActionObserverSetOperationParams, chain, id, extra)
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
	logger.Printf("node.handleBondAsset(%v) => %t %v", s, handled, err)
	if err != nil || handled {
		return err
	}

	handled, err = node.handleTransactionApprovalPayment(ctx, s)
	logger.Printf("node.handleTransactionApprovalPayment(%v) => %t %v", s, handled, err)
	if err != nil || handled {
		return err
	}

	handled, err = node.handleCustomObserverKeyRegistration(ctx, s)
	logger.Printf("node.handleCustomObserverKeyRegistration(%v) => %t %v", s, handled, err)
	if err != nil || handled {
		return err
	}

	_, err = node.handleKeeperResponse(ctx, s)
	return err
}

func (node *Node) handleCustomObserverKeyRegistration(ctx context.Context, s *mixin.Snapshot) (bool, error) {
	if s.AssetID != node.conf.CustomKeyPriceAssetId {
		return false, nil
	}
	extra, _ := base64.RawURLEncoding.DecodeString(s.Memo)
	if len(extra) != 66 {
		return false, nil
	}
	switch extra[0] {
	case common.CurveSecp256k1ECDSABitcoin:
	default:
		return false, nil
	}

	if s.Amount.Cmp(decimal.RequireFromString(node.conf.CustomKeyPriceAmount)) < 0 {
		return true, nil
	}

	observer := hex.EncodeToString(extra[1:34])
	key, err := node.keeperStore.ReadKey(ctx, observer)
	if err != nil {
		return false, err
	} else if key != nil {
		return true, nil
	}

	chainCode := extra[34:66]
	err = bitcoin.CheckDerivation(observer, chainCode, 1000)
	logger.Printf("bitcoin.CheckDerivation(%s, %x) => %v", observer, chainCode, err)
	if err != nil {
		return true, nil
	}

	id := mixin.UniqueConversationID(observer, observer)
	extra = append([]byte{common.RequestRoleObserver}, chainCode...)
	extra = append(extra, common.RequestFlagCustomObserverKey)
	err = node.sendBitcoinKeeperResponse(ctx, observer, common.ActionObserverAddKey, keeper.SafeChainBitcoin, id, extra)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (node *Node) handleTransactionApprovalPayment(ctx context.Context, s *mixin.Snapshot) (bool, error) {
	approval, err := node.store.ReadTransactionApproval(ctx, s.Memo)
	if err != nil || approval == nil {
		return false, err
	}
	params, err := node.keeperStore.ReadLatestOperationParams(ctx, approval.Chain, s.CreatedAt)
	if err != nil || params == nil {
		return false, err
	}
	if s.AssetID != params.OperationPriceAsset {
		return false, nil
	}
	if s.Amount.Cmp(params.OperationPriceAmount) < 0 {
		return true, nil
	}
	return true, node.holderPayTransactionApproval(ctx, s.Memo)
}

func (node *Node) handleKeeperResponse(ctx context.Context, s *mixin.Snapshot) (bool, error) {
	msp := mtg.DecodeMixinExtra(s.Memo)
	if msp == nil {
		return false, nil
	}
	b := common.AESDecrypt(node.aesKey[:], []byte(msp.M))
	op, err := common.DecodeOperation(b)
	logger.Printf("common.DecodeOperation(%x) => %v %v", b, op, err)
	if err != nil || len(op.Extra) != 32 {
		return false, err
	}
	chain := keeper.BitcoinCurveChain(op.Curve)
	params, err := node.keeperStore.ReadLatestOperationParams(ctx, chain, s.CreatedAt)
	if err != nil || params == nil {
		return false, err
	}

	switch s.AssetID {
	case node.conf.AssetId:
		if op.Type == common.ActionBitcoinSafeApproveAccount {
			return false, nil
		}
		if s.Amount.Cmp(decimal.NewFromInt(1)) < 0 {
			return false, nil
		}
	case params.OperationPriceAsset:
		if op.Type != common.ActionBitcoinSafeApproveAccount {
			return false, nil
		}
		if s.Amount.Cmp(params.OperationPriceAmount) < 0 {
			return false, nil
		}
	default:
		return false, nil
	}

	var stx crypto.Hash
	copy(stx[:], op.Extra)
	tx, err := common.ReadKernelTransaction(node.conf.MixinRPC, stx)
	if err != nil {
		panic(stx.String())
	}
	smsp := mtg.DecodeMixinExtra(string(tx.Extra))
	if smsp == nil {
		panic(stx.String())
	}
	data, err := common.Base91Decode(smsp.M)
	if err != nil || len(data) < 32 {
		panic(s.TransactionHash)
	}

	switch op.Type {
	case common.ActionBitcoinSafeProposeTransaction:
		return true, node.keeperSaveTransactionProposal(ctx, data, s.CreatedAt)
	case common.ActionBitcoinSafeApproveTransaction:
		return true, node.keeperCombineBitcoinTransactionSignatures(ctx, data)
	case common.ActionBitcoinSafeProposeAccount, common.ActionEthereumSafeProposeAccount:
		return true, node.keeperSaveAccountProposal(ctx, data, s.CreatedAt)
	case common.ActionBitcoinSafeApproveAccount:
		return true, node.deployBitcoinSafeBond(ctx, data)
	}
	return true, nil
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
