package observer

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	m "github.com/MixinNetwork/safe/apps/mixin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	snapshotsCheckpointKey        = "snapshots-checkpoint"
	mixinWithdrawalsCheckpointKey = "mixin-withdrawals-checkpoint"
	depositNetworkInfoDelay       = 3 * time.Minute
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
	abi.InitFactoryContractAddress(conf.PolygonFactoryAddress)
	return node
}

func (node *Node) Boot(ctx context.Context) {
	err := node.migrate(ctx)
	if err != nil {
		panic(err)
	}
	for _, chain := range []byte{
		keeper.SafeChainBitcoin,
		keeper.SafeChainLitecoin,
		keeper.SafeChainPolygon,
		keeper.SafeChainEthereum,
	} {
		err := node.sendPriceInfo(ctx, chain)
		if err != nil {
			panic(err)
		}

		switch chain {
		case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
			go node.bitcoinNetworkInfoLoop(ctx, chain)
			go node.bitcoinRPCBlocksLoop(ctx, chain)
			go node.bitcoinDepositConfirmLoop(ctx, chain)
			go node.bitcoinTransactionApprovalLoop(ctx, chain)
			go node.bitcoinTransactionSpendLoop(ctx, chain)
		case keeper.SafeChainMVM, keeper.SafeChainPolygon, keeper.SafeChainEthereum:
			go node.ethereumNetworkInfoLoop(ctx, chain)
			go node.ethereumRPCBlocksLoop(ctx, chain)
			go node.ethereumDepositConfirmLoop(ctx, chain)
			go node.ethereumTransactionApprovalLoop(ctx, chain)
			go node.ethereumTransactionSpendLoop(ctx, chain)
		}
	}
	go node.safeKeyLoop(ctx, keeper.SafeChainBitcoin)
	go node.safeKeyLoop(ctx, keeper.SafeChainEthereum)
	go node.mixinWithdrawalsLoop(ctx)
	go node.sendAccountApprovals(ctx)
	node.snapshotsLoop(ctx)
}

func (node *Node) sendPriceInfo(ctx context.Context, chain byte) error {
	var assetId string
	switch chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		_, assetId = node.bitcoinParams(chain)
	case keeper.SafeChainMVM, keeper.SafeChainPolygon, keeper.SafeChainEthereum:
		_, assetId = node.ethereumParams(chain)
	default:
		panic(chain)
	}
	asset, err := node.fetchAssetMeta(ctx, node.conf.OperationPriceAssetId)
	if err != nil {
		return err
	}
	amount := decimal.RequireFromString(node.conf.OperationPriceAmount)
	minimum := decimal.RequireFromString(node.conf.TransactionMinimum)
	logger.Printf("node.sendPriceInfo(%d, %s, %s, %s)", chain, asset.AssetId, amount, minimum)
	amount = amount.Mul(decimal.New(1, 8))
	if amount.Sign() <= 0 || !amount.IsInteger() || !amount.BigInt().IsInt64() {
		panic(node.conf.OperationPriceAmount)
	}
	minimum = minimum.Mul(decimal.New(1, 8))
	if minimum.Sign() <= 0 || !minimum.IsInteger() || !minimum.BigInt().IsInt64() {
		panic(node.conf.TransactionMinimum)
	}
	if minimum.IntPart() < 10000 {
		panic(node.conf.TransactionMinimum)
	}
	dummy := node.bitcoinDummyHolder()
	id := common.UniqueId("ActionObserverSetOperationParams", dummy)
	id = common.UniqueId(id, assetId)
	id = common.UniqueId(id, asset.AssetId)
	id = common.UniqueId(id, amount.String())
	id = common.UniqueId(id, minimum.String())
	extra := []byte{chain}
	extra = append(extra, uuid.Must(uuid.FromString(asset.AssetId)).Bytes()...)
	extra = binary.BigEndian.AppendUint64(extra, uint64(amount.IntPart()))
	extra = binary.BigEndian.AppendUint64(extra, uint64(minimum.IntPart()))
	return node.sendKeeperResponse(ctx, dummy, common.ActionObserverSetOperationParams, chain, id, extra)
}

func (node *Node) saveAccountApprovalSignature(ctx context.Context, addr, sig string) error {
	if !common.CheckTestEnvironment(ctx) {
		safe, err := node.keeperStore.ReadSafeByAddress(ctx, addr)
		if err != nil || (safe != nil && safe.State == common.RequestStateDone) {
			return err
		}
	}
	return node.store.SaveAccountApprovalSignature(ctx, addr, sig)
}

func (node *Node) sendAccountApprovals(ctx context.Context) {
	for {
		as, err := node.store.ListProposedAccountsWithSig(ctx)
		if err != nil {
			panic(err)
		}
		for _, account := range as {
			sp, err := node.keeperStore.ReadSafeProposalByAddress(ctx, account.Address)
			if err != nil {
				panic(err)
			}
			id := common.UniqueId(account.Address, account.Signature)
			rid := uuid.Must(uuid.FromString(sp.RequestId))

			var extra []byte
			var action byte
			var assetId string
			switch sp.Chain {
			case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
				_, assetId = node.bitcoinParams(sp.Chain)
				sig, err := base64.RawURLEncoding.DecodeString(account.Signature)
				if err != nil {
					panic(err)
				}
				action = common.ActionBitcoinSafeApproveAccount
				extra = append(rid.Bytes(), sig...)
			case keeper.SafeChainMVM, keeper.SafeChainPolygon, keeper.SafeChainEthereum:
				_, assetId = node.ethereumParams(sp.Chain)
				sig, err := hex.DecodeString(account.Signature)
				if err != nil {
					panic(err)
				}
				action = common.ActionEthereumSafeApproveAccount
				extra = append(rid.Bytes(), sig...)
			default:
				panic(sp.Chain)
			}
			asset, err := node.store.ReadAssetMeta(ctx, assetId)
			if err != nil || asset == nil {
				panic(err)
			}
			bonded, err := node.checkOrDeployKeeperBond(ctx, sp.Chain, assetId, "", sp.Holder)
			if err != nil {
				panic(fmt.Errorf("node.checkOrDeployKeeperBond(%s) => %v", sp.Holder, err))
			} else if !bonded {
				continue
			}

			logger.Printf("node.sendAccountApprovals(%d, %s, %s, %x)", sp.Chain, sp.Holder, id, extra)
			err = node.sendKeeperResponse(ctx, sp.Holder, byte(action), sp.Chain, id, extra)
			if err != nil {
				panic(err)
			}
			err = node.store.MarkAccountApproved(ctx, sp.Address)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) snapshotsLoop(ctx context.Context) {
	for {
		offset, err := node.readSnapshotsCheckpoint(ctx)
		if err != nil {
			panic(err)
		}
		snapshots, err := node.mixin.ReadSafeSnapshots(ctx, "", offset, "ASC", 500)
		if err != nil {
			logger.Printf("mixin.ReadSafeSnapshots(%s) => %v", offset, err)
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

func (node *Node) handleSnapshot(ctx context.Context, s *mixin.SafeSnapshot) error {
	logger.Verbosef("node.handleSnapshot(%v)", s)
	if s.Amount.Sign() < 0 {
		return nil
	}

	memo, err := hex.DecodeString(s.Memo)
	if err != nil {
		return fmt.Errorf("hex.DecodeString(%s) => %v", s.Memo, err)
	}
	s.Memo = string(memo)

	handled, err := node.handleTransactionApprovalPayment(ctx, s)
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

func (node *Node) mixinWithdrawalsLoop(ctx context.Context) {
	for {
		time.Sleep(time.Second)
		checkpoint, err := node.readMixinWithdrawalsCheckpoint(ctx)
		if err != nil {
			panic(err)
		}
		snapshots, err := m.RPCListSnapshots(ctx, node.conf.MixinRPC, checkpoint, 100)
		if err != nil {
			continue
		}

		for _, s := range snapshots {
			checkpoint = s.Topology
			err := node.processMixinWithdrawalSnapshot(ctx, s)
			logger.Printf("node.processMixinWithdrawalSnapshot(%v) => %v", s, err)
			if err != nil {
				panic(err)
			}
		}
		if len(snapshots) < 100 {
			time.Sleep(time.Second)
		}

		err = node.writeMixinWithdrawalsCheckpoint(ctx, checkpoint)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) processMixinWithdrawalSnapshot(ctx context.Context, s m.RPCSnapshot) error {
	for _, t := range s.Transaction {
		if len(t.Output) == 0 {
			continue
		}
		out := t.Output[0]
		if out.Type != mixinnet.OutputTypeWithdrawalClaim {
			continue
		}

		tx, err := m.RPCGetTransaction(ctx, node.conf.MixinRPC, t.References[0])
		if err != nil {
			return err
		}
		asset, err := node.fetchMixinNetworkAsset(ctx, tx.Asset)
		if err != nil {
			return err
		}
		chain := node.getSafeChainFromAssetChainId(asset.ChainId)
		if chain == 0 {
			continue
		}

		extra, err := hex.DecodeString(t.Extra)
		if err != nil {
			return err
		}
		hash := string(extra[64:])
		switch chain {
		case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
			rpc, _ := node.bitcoinParams(chain)
			btx, err := bitcoin.RPCGetTransaction(chain, rpc, hash)
			if err != nil {
				return err
			}
			return node.bitcoinProcessTransaction(ctx, btx, chain)
		case keeper.SafeChainEthereum, keeper.SafeChainMVM, keeper.SafeChainPolygon:
			rpc, _ := node.ethereumParams(chain)
			etx, err := ethereum.RPCGetTransactionByHash(rpc, hash)
			if err != nil {
				return err
			}
			return node.ethereumProcessTransaction(ctx, etx, chain)
		}
	}
	return nil
}

func (node *Node) handleCustomObserverKeyRegistration(ctx context.Context, s *mixin.SafeSnapshot) (bool, error) {
	if s.AssetID != node.conf.CustomKeyPriceAssetId {
		return false, nil
	}
	extra, _ := base64.RawURLEncoding.DecodeString(s.Memo)
	if len(extra) != 66 {
		return false, nil
	}

	switch extra[0] {
	case common.CurveSecp256k1ECDSABitcoin:
	case common.CurveSecp256k1ECDSAEthereum:
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

	chain := keeper.SafeCurveChain(extra[0])
	id := common.UniqueId(observer, observer)
	extra = append([]byte{common.RequestRoleObserver}, chainCode...)
	extra = append(extra, common.RequestFlagCustomObserverKey)
	err = node.sendKeeperResponse(ctx, observer, common.ActionObserverAddKey, chain, id, extra)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (node *Node) handleTransactionApprovalPayment(ctx context.Context, s *mixin.SafeSnapshot) (bool, error) {
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
	return true, node.holderPayTransactionApproval(ctx, approval.Chain, s.Memo)
}

func (node *Node) handleKeeperResponse(ctx context.Context, s *mixin.SafeSnapshot) (bool, error) {
	g, t, m := mtg.DecodeMixinExtra(hex.EncodeToString([]byte(s.Memo)))
	if g == "" && t == "" && m == "" {
		return false, nil
	}
	b := common.AESDecrypt(node.aesKey[:], []byte(m))
	op, err := common.DecodeOperation(b)
	logger.Printf("common.DecodeOperation(%x) => %v %v", b, op, err)
	if err != nil || len(op.Extra) != 16 {
		return false, err
	}
	chain := keeper.SafeCurveChain(op.Curve)
	params, err := node.keeperStore.ReadLatestOperationParams(ctx, chain, s.CreatedAt)
	if err != nil || params == nil {
		return false, err
	}

	switch s.AssetID {
	case node.conf.AssetId:
		switch op.Type {
		case common.ActionBitcoinSafeApproveAccount, common.ActionEthereumSafeApproveAccount:
			return false, nil
		}
		if s.Amount.Cmp(decimal.NewFromInt(1)) < 0 {
			return false, nil
		}
	case params.OperationPriceAsset:
		switch op.Type {
		case common.ActionBitcoinSafeApproveAccount, common.ActionEthereumSafeApproveAccount:
		default:
			return false, nil
		}
		if s.Amount.Cmp(params.OperationPriceAmount) < 0 {
			return false, nil
		}
	default:
		return false, nil
	}

	rid := uuid.FromBytesOrNil(op.Extra).String()
	tx, err := common.SafeReadTransactionRequestUntilSufficient(ctx, node.mixin, rid)
	if err != nil {
		return false, err
	}
	g, t, m = mtg.DecodeMixinExtra(tx.Extra)
	if g == "" && t == "" && m == "" {
		data, _ := hex.DecodeString(tx.Extra)
		m = string(data)
	}
	data, err := common.Base91Decode(m)
	if err != nil || len(data) < 32 {
		panic(fmt.Errorf("common.Base91Decode(%s) => %d %v", m, len(data), err))
	}

	switch op.Type {
	case common.ActionBitcoinSafeProposeTransaction, common.ActionEthereumSafeProposeTransaction:
		return true, node.keeperSaveTransactionProposal(ctx, chain, data, s.CreatedAt)
	case common.ActionBitcoinSafeApproveTransaction:
		return true, node.keeperCombineBitcoinTransactionSignatures(ctx, data)
	case common.ActionEthereumSafeApproveTransaction:
		return true, node.keeperVerifyEthereumTransactionSignatures(ctx, data)
	case common.ActionBitcoinSafeProposeAccount, common.ActionEthereumSafeProposeAccount:
		return true, node.keeperSaveAccountProposal(ctx, chain, data, s.CreatedAt)
	case common.ActionBitcoinSafeApproveAccount:
		return true, node.deployBitcoinSafeBond(ctx, data)
	case common.ActionEthereumSafeApproveAccount:
		return true, node.deployEthereumGnosisSafeAccount(ctx, data)
	}
	return true, nil
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

func (node *Node) readDepositCheckpoint(ctx context.Context, chain byte) (int64, error) {
	key := depositCheckpointKey(chain)
	min := depositCheckpointDefault(chain)
	ckt, err := node.store.ReadProperty(ctx, key)
	if err != nil || ckt == "" {
		return min, err
	}
	checkpoint, err := strconv.ParseInt(ckt, 10, 64)
	if err != nil {
		panic(ckt)
	}
	if checkpoint < min {
		checkpoint = min
	}
	return checkpoint, nil
}

func (node *Node) readMixinWithdrawalsCheckpoint(ctx context.Context) (uint64, error) {
	val, err := node.store.ReadProperty(ctx, mixinWithdrawalsCheckpointKey)
	if err != nil || val == "" {
		return 4655227, err
	}
	return strconv.ParseUint(val, 10, 64)
}

func (node *Node) writeMixinWithdrawalsCheckpoint(ctx context.Context, offset uint64) error {
	return node.store.WriteProperty(ctx, mixinWithdrawalsCheckpointKey, fmt.Sprint(offset))
}

func (node *Node) safeUser() bot.SafeUser {
	return bot.SafeUser{
		UserId:            node.conf.App.AppId,
		SessionId:         node.conf.App.SessionId,
		ServerPublicKey:   node.conf.App.ServerPublicKey,
		SessionPrivateKey: node.conf.App.SessionPrivateKey,
		SpendPrivateKey:   node.conf.App.SpendPrivateKey,
	}
}

func depositCheckpointDefault(chain byte) int64 {
	switch chain {
	case keeper.SafeChainBitcoin:
		return 802220
	case keeper.SafeChainLitecoin:
		return 2523300
	case keeper.SafeChainMVM:
		return 52680000
	case keeper.SafeChainPolygon:
		return 52950000
	case keeper.SafeChainEthereum:
		return 19175473
	default:
		panic(chain)
	}
}

func depositCheckpointKey(chain byte) string {
	switch chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		return fmt.Sprintf("bitcoin-deposit-checkpoint-%d", chain)
	case keeper.SafeChainEthereum, keeper.SafeChainPolygon, keeper.SafeChainMVM:
		return fmt.Sprintf("ethereum-deposit-checkpoint-%d", chain)
	default:
		panic(chain)
	}
}

func (node *Node) safeTraceId(params ...string) string {
	traceId := common.UniqueId(node.conf.PrivateKey, node.conf.PrivateKey)
	for _, id := range params {
		traceId = common.UniqueId(traceId, id)
	}
	return traceId
}

func (node *Node) getChainFinalizationDelay(chain byte) int64 {
	switch chain {
	case keeper.SafeChainBitcoin:
		return 3
	case keeper.SafeChainLitecoin:
		return 6
	case keeper.SafeChainEthereum:
		return 32
	case keeper.SafeChainPolygon:
		return 512
	default:
		panic(chain)
	}
}

func (node *Node) getSafeChainFromAssetChainId(chainId string) byte {
	var chain byte
	switch chainId {
	case keeper.SafeBitcoinChainId:
		chain = keeper.SafeChainBitcoin
	case keeper.SafeLitecoinChainId:
		chain = keeper.SafeChainLitecoin
	case keeper.SafeEthereumChainId:
		chain = keeper.SafeChainEthereum
	case keeper.SafeMVMChainId:
		chain = keeper.SafeChainMVM
	case keeper.SafePolygonChainId:
		chain = keeper.SafeChainPolygon
	}
	return chain
}
