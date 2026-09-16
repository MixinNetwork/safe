package mtg

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/util"
	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/gofrs/uuid/v5"
	"github.com/pelletier/go-toml"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

const (
	USDTAssetId = "218bc6f4-7927-3f8e-8568-3a3725b74361"
	SOLAssetId  = "64692c23-8971-4cf4-84a7-4dd1271dd887"
	testSender  = "e14c1573-3aca-48b1-b437-766b4757b50d"

	testWithdrawalDestination = "73yoz7kK3zgh2ScD9aTJpXCrKHETi1xyEKfMTH95ugff"
	testWithdrawalAmount      = "0.0049"
	testWithdrawalMemo        = "withdrawal-test"
)

type Node struct {
	Group *Group
}

var actionResult map[string]string

func (n *Node) ProcessOutput(ctx context.Context, a *Action) ([]*Transaction, string) {
	txs, compaction := n.processOutput(ctx, a)
	liquidity := a.LiquidityRequirement()
	if liquidity != nil {
		if len(txs) > 0 || compaction != liquidity.AssetId {
			panic(a.OutputId)
		}
		return nil, a.CustodianCompactionString()
	}
	return txs, compaction
}

func (n *Node) processOutput(ctx context.Context, a *Action) ([]*Transaction, string) {
	if actionResult[a.OutputId] != "" {
		data, err := hex.DecodeString(actionResult[a.OutputId])
		if err != nil {
			panic(err)
		}
		txs, err := DeserializeTransactions(data)
		if err != nil {
			panic(err)
		}
		return txs, ""
	}

	b, err := hex.DecodeString(a.Extra)
	if err != nil {
		panic(err)
	}
	b, err = base64.RawStdEncoding.DecodeString(string(b))
	if err != nil {
		return []*Transaction{}, ""
	}
	memo := string(b)
	items := util.SplitIds(memo, ",")

	var txs []*Transaction
	var storageTraceId string
	for _, tx := range items {
		switch tx {
		case "storage":
			extra := []byte("storage-memo")
			enough := a.CheckAssetBalanceForStorageAt(ctx, extra)
			if !enough {
				panic(a.Sequence)
			}
			t := a.BuildStorageTransaction(ctx, extra)
			if t == nil {
				return nil, StorageAssetId
			}
			storageTraceId = t.TraceId
			txs = append(txs, t)
		case "withdrawal":
			tid := "cf0564ba-bf51-4e8c-b504-3beb6c5c65e3"
			t := a.BuildWithdrawTransaction(ctx, tid, SOLAssetId, testWithdrawalAmount, testWithdrawalMemo, testWithdrawalDestination, "")
			if t == nil {
				return nil, SOLAssetId
			}
			txs = append(txs, t)
		default:
			amt := decimal.RequireFromString(tx)
			balance := a.CheckAssetBalanceAt(ctx, a.AssetId)
			if balance.Cmp(amt) < 0 {
				return nil, USDTAssetId
			}

			amount := amt.String()
			id := UniqueId(amount, testSender)
			var t *Transaction
			if storageTraceId != "" {
				t = a.BuildTransactionWithStorageTraceId(ctx, id, UniqueId(a.AppId, "opponent"), a.AssetId, amount, "", n.Group.GetMembers(), n.Group.GetThreshold(), storageTraceId)
			} else {
				t = a.BuildTransaction(ctx, id, UniqueId(a.AppId, "opponent"), a.AssetId, amount, "", n.Group.GetMembers(), n.Group.GetThreshold())
			}
			if t == nil {
				return nil, a.AssetId
			}
			txs = append(txs, t)
		}
	}

	if actionResult[a.OutputId] == "" {
		data := SerializeTransactions(txs)
		actionResult[a.OutputId] = hex.EncodeToString(data)
	}

	return txs, ""
}

func TestMTGExtra(t *testing.T) {
	require := require.New(t)
	id := uuid.Must(uuid.NewV4()).String()
	memo := "123"

	extra := EncodeMixinExtraBase64(id, []byte(memo))
	a, m := DecodeMixinExtraHEX(hex.EncodeToString([]byte(extra)))
	require.Equal(id, a)
	require.Equal(memo, string(m))
}

func TestMTGCompaction(t *testing.T) {
	require := require.New(t)
	ctx, node := testBuildGroup(require)
	require.NotNil(node)
	defer teardownTestDatabase(node.Group.store)

	count := OutputsBatchSize*5 + 1
	amount := "0.0181"
	os := testDrainInitialOutputs(ctx, require, node.Group, count, amount)
	out := testBuildOutput(node.Group, require, USDTAssetId, "0.0036", "", SafeUtxoStateUnspent, uint64(os[len(os)-1].Sequence+10), "")
	err := node.Group.store.WriteAction(ctx, out, ActionStateDone)
	require.Nil(err)
	balance := decimal.RequireFromString(amount).Add(decimal.RequireFromString("0.0036")).String()

	as, err := node.Group.store.ListActions(ctx, ActionStateDone, 0)
	require.Nil(err)
	require.Len(as, count+1)
	as, err = node.Group.store.ListActions(ctx, ActionStateInitial, 0)
	require.Nil(err)
	require.Len(as, 1)
	actionId := as[0].OutputId
	appId := as[0].AppId
	hash := as[0].TransactionHash
	wkr := node.Group.FindWorker(as[0].AppId)
	require.NotNil(wkr)

	for range 5 {
		// compaction would not change the balance
		_, b := testGetTotalBalanceByAsset(ctx, *node.Group, as[0].AppId, USDTAssetId)
		require.Equal(balance, b.String())

		// process normal action and build compaction tx
		as, err = node.Group.store.ListActions(ctx, ActionStateInitial, 0)
		require.Nil(err)
		require.Len(as, 1)
		if as[0].restoreSequence > 0 {
			as[0].Sequence = as[0].restoreSequence
		}
		err = node.Group.handleActionsQueue(ctx)
		require.Nil(err)
		as, err = node.Group.store.ListActions(ctx, ActionStateInitial, 0)
		require.Nil(err)
		require.Len(as, 0)
		as, err = node.Group.store.ListActions(ctx, ActionStateRestorable, 0)
		require.Nil(err)
		require.Len(as, 1)

		// write output from compaction tx
		out := testHandleCompactionTransaction(ctx, require, node.Group, hash)
		node.Group.processSafeOutput(ctx, out)
		as, err = node.Group.store.ListActions(ctx, ActionStateInitial, 0)
		require.Nil(err)
		require.Len(as, 1)

		// restore action
		err = node.Group.handleActionsQueue(ctx)
		require.Nil(err)
		as, err = node.Group.store.ListActions(ctx, ActionStateRestorable, 0)
		require.Nil(err)
		require.Len(as, 0)
		as, err = node.Group.store.ListActions(ctx, ActionStateInitial, 0)
		require.Nil(err)
		require.Len(as, 1)
		require.Equal(as[0].OutputId, actionId)
	}
	os, b := testGetTotalBalanceByAsset(ctx, *node.Group, appId, USDTAssetId)
	require.Len(os, 7)
	require.Equal(balance, b.String())

	err = node.Group.handleActionsQueue(ctx)
	require.Nil(err)
	ts, _, err := node.Group.store.ListTransactions(ctx, TransactionStateInitial, 0)
	require.Nil(err)
	require.Len(ts, 1)
	tx := ts[0]
	tx.consumed = node.Group.ListOutputsForTransaction(ctx, tx.TraceId, tx.Sequence)
	for _, o := range tx.consumed {
		tx.consumedIds = append(tx.consumedIds, o.OutputId)
	}
	tsb := SerializeTransactions(ts)
	dts, err := DeserializeTransactions(tsb)
	require.Nil(err)
	require.Len(dts, 1)
	require.True(ts[0].Equal(dts[0]))

	a, err := node.Group.store.ReadAction(ctx, actionId)
	require.Nil(err)
	require.Equal(ActionStateDone, a.ActionState)
	os, b = testGetTotalBalanceByAsset(ctx, *node.Group, appId, USDTAssetId)
	require.Len(os, 1)
	require.Equal("0.0036", b.String())
}

func TestCheckMultisigRequestRawTransaction(t *testing.T) {
	require := require.New(t)

	build := func(extra string) *common.VersionedTransaction {
		tx := common.NewTransactionV5(crypto.Sha256Hash([]byte(USDTAssetId)))
		tx.AddInput(crypto.Sha256Hash([]byte("output")), 0)
		tx.Extra = []byte(extra)
		return tx.AsVersioned()
	}

	ver := build("honest")
	req := &mixin.SafeMultisigRequest{
		RequestID:      uuid.Must(uuid.NewV4()).String(),
		RawTransaction: hex.EncodeToString(ver.Marshal()),
	}
	rver, err := CheckMultisigRequestRawTransaction(req, ver)
	require.Nil(err)
	require.Equal(ver.PayloadHash(), rver.PayloadHash())

	// a squatted request with a different raw transaction must be rejected
	other := build("theft")
	req.RawTransaction = hex.EncodeToString(other.Marshal())
	_, err = CheckMultisigRequestRawTransaction(req, ver)
	require.NotNil(err)
	require.True(strings.Contains(err.Error(), "raw transaction mismatch"))

	// malformed raw transactions must be rejected
	req.RawTransaction = "ff"
	_, err = CheckMultisigRequestRawTransaction(req, ver)
	require.NotNil(err)
}

func TestMTGCheckTxs(t *testing.T) {
	require := require.New(t)
	ctx, node := testBuildGroup(require)
	require.NotNil(node)
	defer teardownTestDatabase(node.Group.store)

	testDrainInitialOutputs(ctx, require, node.Group, OutputsBatchSize+1, "0.003,0.0008")

	as, err := node.Group.store.ListActions(ctx, ActionStateDone, 0)
	require.Nil(err)
	require.Len(as, OutputsBatchSize+1)
	as, err = node.Group.store.ListActions(ctx, ActionStateInitial, 0)
	require.Nil(err)
	require.Len(as, 1)

	wkr := node.Group.FindWorker(as[0].AppId)
	require.NotNil(wkr)
	err = node.Group.handleActionsQueue(ctx)
	require.NotNil(err)
	require.True(strings.Contains(err.Error(), "insufficient outputs"))
}

func TestMTGStorage(t *testing.T) {
	require := require.New(t)
	ctx, node := testBuildGroup(require)
	require.NotNil(node)
	defer teardownTestDatabase(node.Group.store)

	testDrainInitialOutputs(ctx, require, node.Group, OutputsBatchSize+1, "storage,0.0001")

	as, err := node.Group.store.ListActions(ctx, ActionStateDone, 0)
	require.Nil(err)
	require.Len(as, OutputsBatchSize+1)
	as, err = node.Group.store.ListActions(ctx, ActionStateInitial, 0)
	require.Nil(err)
	require.Len(as, 1)

	wkr := node.Group.FindWorker(as[0].AppId)
	require.NotNil(wkr)
	err = node.Group.handleActionsQueue(ctx)
	require.Nil(err)

	txs, _, err := node.Group.store.ListTransactions(ctx, TransactionStateInitial, 0)
	require.Nil(err)
	require.Len(txs, 2)
	require.True(txs[1].storage)
	require.Equal(txs[1].TraceId, txs[0].storageTraceId)

	ver := node.Group.signTransaction(ctx, txs[0])
	require.Nil(ver)
	tx, err := node.Group.store.ReadTransactionByTraceId(ctx, txs[0].TraceId)
	require.Nil(err)
	require.Equal(TransactionStateInitial, tx.State)

	ver = node.Group.signTransaction(ctx, txs[1])
	require.NotNil(ver)
	err = node.Group.store.FinishTransaction(ctx, txs[1].TraceId)
	require.Nil(err)
	ver = node.Group.signTransaction(ctx, txs[0])
	require.NotNil(ver)

	storage, err := node.Group.store.ReadTransactionByTraceId(ctx, txs[1].TraceId)
	require.Nil(err)
	tx, err = node.Group.store.ReadTransactionByTraceId(ctx, txs[0].TraceId)
	require.Nil(err)
	require.NotEqual(TransactionStateInitial, tx.State)
	require.Equal(storage.Hash.String(), tx.references[0].String())
}

func TestMTGWithdrawal(t *testing.T) {
	require := require.New(t)
	ctx, node := testBuildGroup(require)
	require.NotNil(node)
	defer teardownTestDatabase(node.Group.store)

	d := decimal.RequireFromString("0.005")
	err := node.Group.store.WriteAction(ctx, &UnifiedOutput{
		OutputId:             "7514b939-db92-3d31-abf4-7841f035e400",
		TransactionRequestId: "cf0564ba-bf51-4e8c-b504-3beb6c5c65e2",
		TransactionHash:      "01c43005fd06e0b8f06a0af04faf7530331603e352a11032afd0fd9dbd84e8ee",
		OutputIndex:          0,
		AssetId:              SOLAssetId,
		Amount:               d,
		SendersThreshold:     int64(1),
		Senders:              []string{testSender},
		ReceiversThreshold:   int64(node.Group.GetThreshold()),
		Extra:                "",
		State:                SafeUtxoStateUnspent,
		Sequence:             4655227,
		AppId:                node.Group.GroupId,
	}, ActionStateDone)
	require.Nil(err)

	testDrainInitialOutputs(ctx, require, node.Group, OutputsBatchSize+1, "withdrawal")
	as, err := node.Group.store.ListActions(ctx, ActionStateInitial, 0)
	require.Nil(err)
	require.Len(as, 1)
	wkr := node.Group.FindWorker(as[0].AppId)
	require.NotNil(wkr)
	err = node.Group.handleActionsQueue(ctx)
	require.Nil(err)

	txs, _, err := node.Group.store.ListTransactions(ctx, TransactionStateInitial, 0)
	require.Nil(err)
	require.Len(txs, 1)
	tx, err := Deserialize(txs[0].Serialize())
	require.Nil(err)
	require.Equal(testWithdrawalAmount, tx.Amount)
	require.Equal(testWithdrawalMemo, tx.Memo)
	require.Equal(SOLAssetId, tx.AssetId)
	require.Equal(testWithdrawalDestination, tx.Destination.String)
	require.Equal("", tx.Tag.String)
	require.False(tx.WithdrawalHash.Valid)

	outputs := node.Group.ListOutputsForTransaction(ctx, tx.TraceId, tx.Sequence)
	require.True(len(outputs) > 0)
	ver, consumed, change, err := node.Group.buildRawTransaction(ctx, tx, outputs)
	require.Nil(err)
	require.True(len(outputs) == len(consumed))
	raw := hex.EncodeToString(ver.Marshal())
	require.Equal(
		"77770005481360491383ebd4f0f97543f3440313b48b8fd06dcfa5a0c2cabe4252d3a8eb000101c43005fd06e0b8f06a0af04faf7530331603e352a11032afd0fd9dbd84e8ee0000000000000000000200a10003077a100000000000000000000000000000000000000000000000000000000000000000000000007777002c3733796f7a376b4b337a6768325363443961544a705843724b48455469317879454b664d544839357567666600000000000227100002f5c8b3dbb7a5b2f7e1e4640d9f61c142cda547917f227ba21ebc5d554651c50d18f71fbe1b5055f3d882a4ae2813fad315bf0dcb5a0e60f091121db882baff77f18e0e276648b1d42063f8bcf9d5a57252f4048c9939ded0999a0e263716976e0003fffe02000000000000000f7769746864726177616c2d746573740000",
		raw,
	)
	_, err = node.Group.updateTxWithOutputs(ctx, tx, consumed, &mixin.SafeMultisigRequest{
		RequestID:       tx.RequestID(),
		TransactionHash: "f45e51276a031a46d25998605324e8a3f1b720d33f66dc226018448f53bda4c4",
		RawTransaction:  raw,
	}, change)
	require.Nil(err)
	require.Equal(common.NewIntegerFromString("0.0001"), change)

	txs, _, err = node.Group.store.ListTransactions(ctx, TransactionStateInitial, 0)
	require.Nil(err)
	require.Len(txs, 0)
	txs, _, err = node.Group.store.ListTransactions(ctx, TransactionStateSigned, 0)
	require.Nil(err)
	require.Len(txs, 1)

	err = node.Group.store.FinishTransaction(ctx, tx.TraceId)
	require.Nil(err)
	txs, _, err = node.Group.store.ListTransactions(ctx, TransactionStateSigned, 0)
	require.Nil(err)
	require.Len(txs, 0)
	txs, _, err = node.Group.store.ListTransactions(ctx, TransactionStateSnapshot, 0)
	require.Nil(err)
	require.Len(txs, 1)
	os, err := node.Group.store.ListOutputsForAsset(ctx, tx.AppId, tx.AssetId, 0, math.MaxInt64, SafeUtxoStateUnreceived, 0)
	require.Nil(err)
	require.Len(os, 1)
	cu := os[0]

	tx = txs[0]
	tx.consumed = node.Group.ListOutputsForTransaction(ctx, tx.TraceId, tx.Sequence)
	for _, o := range tx.consumed {
		tx.consumedIds = append(tx.consumedIds, o.OutputId)
	}
	tsb := SerializeTransactions(txs)
	require.Equal("0100c8cf0564babf514e8cb5043beb6c5c65e37201c7d7eac8374ca5ec9dcb47a38fa57201c7d7eac8374ca5ec9dcb47a38fa5276192fd01413e56a50ff04061a218770d64692c2389714cf484a74dd1271dd8870006302e30303439000f7769746864726177616c2d7465737400000000004708a100000000000000000000000000000000000000017514b939db923d31abf47841f035e4007777002c3733796f7a376b4b337a6768325363443961544a705843724b48455469317879454b664d54483935756766660000", hex.EncodeToString(tsb))
	dtxs, err := DeserializeTransactions(tsb)
	require.Nil(err)
	require.Len(dtxs, 1)
	tx.Hash = crypto.Hash{}
	tx.Raw = nil
	require.True(txs[0].Equal(dtxs[0]))

	out := &UnifiedOutput{
		OutputId:             uuid.Must(uuid.NewV4()).String(),
		TransactionRequestId: cu.TransactionRequestId,
		TransactionHash:      cu.TransactionHash,
		OutputIndex:          cu.OutputIndex,
		AssetId:              cu.AssetId,
		Amount:               cu.Amount,
		State:                SafeUtxoStateUnspent,
		AppId:                cu.AppId,
	}
	err = node.Group.store.WriteAction(ctx, out, ActionStateInitial)
	require.Nil(err)
	os, err = node.Group.store.ListOutputsForAsset(ctx, tx.AppId, tx.AssetId, 0, tx.Sequence, SafeUtxoStateUnreceived, 500)
	require.Nil(err)
	require.Len(os, 0)
	o, err := node.Group.store.ReadOutputById(ctx, cu.OutputId)
	require.Nil(err)
	require.Nil(o)
}

func TestLiquidityRequirementSerialize(t *testing.T) {
	requirement := &LiquidityRequirement{
		AssetId:        "218bc6f4-7927-3f8e-8568-3a3725b74361",
		Amount:         decimal.RequireFromString("2.1"),
		InternalAmount: decimal.RequireFromString("7.9"),
		InternalInputIds: []string{
			"cf0564ba-bf51-4e8c-b504-3beb6c5c65e3",
			"df0564ba-bf51-4e8c-b504-3beb6c5c65e3",
		},
	}
	b := requirement.Serialize()
	require.Equal(t, "218bc6f479273f8e85683a3725b743610003322e310003372e390002cf0564babf514e8cb5043beb6c5c65e3df0564babf514e8cb5043beb6c5c65e3", hex.EncodeToString(b))

	actual, err := DeserializeLiquidityRequirement(b)
	require.NoError(t, err)
	require.True(t, requirement.equal(actual))
}

func testGetTotalBalanceByAsset(ctx context.Context, group Group, appId, assetId string) ([]*UnifiedOutput, decimal.Decimal) {
	os := group.ListOutputsForAsset(ctx, appId, assetId, 0, 50454214, SafeUtxoStateUnspent, 0)
	total := decimal.Zero
	for _, o := range os {
		total = total.Add(o.Amount)
	}
	return os, total
}

func testHandleCompactionTransaction(ctx context.Context, require *require.Assertions, group *Group, hash string) *UnifiedOutput {
	ts, _, err := group.store.ListTransactions(ctx, TransactionStateInitial, 0)
	require.Nil(err)
	require.Len(ts, 1)

	tx := ts[0]
	require.True(tx.compaction)
	outputs := group.ListOutputsForAsset(ctx, tx.AppId, tx.AssetId, 0, tx.Sequence, SafeUtxoStateAssigned, OutputsBatchSize)
	require.Len(outputs, 36)
	ver, consumed, change, err := group.buildRawTransaction(ctx, tx, outputs)
	require.Nil(err)
	require.Equal(common.NewInteger(0), change)
	require.Len(consumed, 36)
	require.Len(ver.References, 1)
	require.Len(ver.References, 1)
	require.Equal(ver.References[0].String(), hash)

	tx.Hash = ver.PayloadHash()
	tx.Raw = ver.Marshal()
	tx.State = TransactionStateSnapshot
	for _, out := range consumed {
		out.State = SafeUtxoStateSpent
		out.SignedBy = tx.Hash.String()
	}
	err = group.store.UpdateTxWithOutputs(ctx, tx, consumed, change)
	require.Nil(err)

	return testBuildActionFromTx(require, group, tx)
}

func testBuildActionFromTx(require *require.Assertions, group *Group, tx *Transaction) *UnifiedOutput {
	extra := EncodeMixinExtraBase64(tx.AppId, []byte(tx.Memo))
	extra = hex.EncodeToString([]byte(extra))
	return testBuildOutput(group, require, tx.AssetId, tx.Amount, extra, SafeUtxoStateUnspent, tx.Sequence+100, tx.Hash.String())
}

func testDrainInitialOutputs(ctx context.Context, require *require.Assertions, group *Group, count int, memo string) []*UnifiedOutput {
	start := 4655228

	out := testBuildOutput(group, require, StorageAssetId, "1", "", SafeUtxoStateUnspent, uint64(start), "")
	err := group.store.WriteAction(ctx, out, ActionStateDone)
	require.Nil(err)

	var os []*UnifiedOutput
	for i := range count {
		extra := ""
		state := ActionStateDone
		if i+1 == count {
			extra = base64.RawStdEncoding.EncodeToString([]byte(memo))
			extra = hex.EncodeToString([]byte(extra))
			state = ActionStateInitial
		}
		out := testBuildOutput(group, require, USDTAssetId, "0.0001", extra, SafeUtxoStateUnspent, uint64(start+i+1), "")

		err := group.store.WriteAction(ctx, out, state)
		require.Nil(err)
		os = append(os, out)
	}
	return os
}

func testBuildOutput(group *Group, require *require.Assertions, asset, amount string, extra string, state SafeUtxoState, sequence uint64, hash string) *UnifiedOutput {
	oid := UniqueId("output", fmt.Sprintf("%s:%s:%s:%s:%d", amount, extra, extra, state, sequence))
	rid := UniqueId("request", oid)
	h := crypto.Sha256Hash(uuid.FromStringOrNil(oid).Bytes())
	if hash != "" {
		hash, err := crypto.HashFromString(hash)
		require.Nil(err)
		h = hash
	}
	oid = mixin.UniqueConversationID(fmt.Sprintf("%s:%d", h, 0), "")
	amt := decimal.RequireFromString(amount)

	return &UnifiedOutput{
		OutputId:             oid,
		TransactionRequestId: rid,
		TransactionHash:      h.String(),
		OutputIndex:          0,
		AssetId:              asset,
		Amount:               amt,
		SendersThreshold:     int64(1),
		Senders:              []string{testSender},
		ReceiversThreshold:   int64(group.GetThreshold()),
		Extra:                extra,
		State:                state,
		Sequence:             sequence,
		AppId:                group.GroupId,
	}
}

func testBuildGroup(require *require.Assertions) (context.Context, *Node) {
	logger.SetLevel(logger.INFO)
	ctx := context.Background()
	ctx = util.EnableTestEnvironment(ctx)

	f, _ := os.ReadFile("./example.toml")
	var conf Configuration
	err := toml.Unmarshal(f, &conf)
	require.Nil(err)

	root, err := os.MkdirTemp("", "mtg-test")
	require.Nil(err)
	conf.StoreDir = root
	if !strings.HasPrefix(conf.StoreDir, "/tmp") && !strings.HasPrefix(conf.StoreDir, "/var/folders") {
		panic(root)
	}
	store, err := OpenSQLite3Store(conf.StoreDir + "/mtg.sqlite3")
	require.Nil(err)

	group, err := BuildGroup(ctx, store, &conf)
	require.Nil(err)
	group.groupSize = 1
	group.EnableDebug()

	n := &Node{
		Group: group,
	}
	group.AttachWorker(group.GroupId, n)

	d := DepositEntry{
		Destination: "213",
		Tag:         "",
	}
	group.RegisterDepositEntry(group.GroupId, d)

	app := group.FindAppByEntry("")
	require.Equal("", app)
	app = group.FindAppByEntry(d.UniqueKey())
	require.Equal(group.GroupId, app)

	ns, err := group.store.ListIterations(ctx)
	require.Nil(err)
	require.Len(ns, 5)

	require.Equal("da99ddc3cac7c96bdd6107275dd6d9d44348a229dcf4df74eba0f77ab8471883", group.GenesisId())
	return ctx, n
}

func (s *SQLite3Store) ReadAction(ctx context.Context, id string) (*Action, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer rollBack(tx)

	return s.readAction(ctx, tx, id)
}

func teardownTestDatabase(store *SQLite3Store) {
	dropTablesDDL := `
		DROP TABLE IF EXISTS properties;
		DROP TABLE IF EXISTS iterations;
		DROP TABLE IF EXISTS actions;
		DROP TABLE IF EXISTS outputs;
		DROP TABLE IF EXISTS transactions;
		DROP TABLE IF EXISTS external_balances;
		DROP TABLE IF EXISTS liquidity_requests;
		DROP TABLE IF EXISTS custodian_transfers;
	`
	_, err := store.db.Exec(dropTablesDDL)
	if err != nil {
		panic(err)
	}
}

func init() {
	actionResult = make(map[string]string)
}

// This worker has fixed payouts so replay exercises MTG reservations without
// depending on keeper/signer adaptation or application result caches.
type custodianFlowWorker struct{}

func (*custodianFlowWorker) ProcessOutput(ctx context.Context, a *Action) ([]*Transaction, string) {
	_, memo := DecodeMixinExtraHEX(a.Extra)
	if string(memo) != "custodian-test-pay" {
		return nil, ""
	}
	var txs []*Transaction
	for i, amount := range []string{"7", "2"} {
		tx := a.BuildTransaction(ctx, UniqueId(a.OutputId, fmt.Sprintf("payout:%d", i)), a.AppId, USDTAssetId, amount, "", []string{testSender}, 1)
		if tx == nil {
			if liquidity := a.LiquidityRequirement(); liquidity != nil {
				return nil, liquidity.CompactionString()
			}
			return nil, USDTAssetId
		}
		txs = append(txs, tx)
	}
	return txs, ""
}

func TestMTGCustodianFlow(t *testing.T) {
	r := require.New(t)
	ctx := util.EnableTestEnvironment(context.Background())
	data, err := os.ReadFile("example.toml")
	r.NoError(err)
	var conf Configuration
	r.NoError(toml.Unmarshal(data, &conf))
	conf.StoreDir = t.TempDir()
	conf.GroupSize = 1
	conf.Custodian = CustodianConfiguration{
		MixAddress:     mixin.RequireNewMixAddress([]string{testSender, "194ac88f-4671-3976-b60a-09064f1811e8"}, 2).String(),
		ConversationId: "294ac88f-4671-3976-b60a-09064f1811e8",
		Requesters:     []string{testSender},
	}
	path := filepath.Join(conf.StoreDir, "mtg.sqlite3")
	legacy, err := sql.Open("sqlite3", path)
	r.NoError(err)
	_, err = legacy.Exec(strings.Replace(SCHEMA, "  reserved_by          VARCHAR NOT NULL,\n", "", 1))
	r.NoError(err)
	r.NoError(legacy.Close())
	store, err := OpenSQLite3Store(path)
	r.NoError(err)
	g, err := BuildGroup(ctx, store, &conf)
	r.NoError(err)
	g.EnableDebug()
	g.AttachWorker(g.GroupId, &custodianFlowWorker{})
	sequence := conf.Genesis.Epoch
	t.Cleanup(func() { r.NoError(g.store.Close()) })

	sequence++
	hotTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(USDTAssetId)))
	hotTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
	hotTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, nil))
	hotTx.Outputs = append(hotTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString("8"), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
	hotVer := hotTx.AsVersioned()
	hotHash := hotVer.PayloadHash().String()
	r.NoError(g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", hotHash), base64.RawURLEncoding.EncodeToString(hotVer.Marshal())))
	hot := testBuildOutput(g, r, USDTAssetId, "8", hex.EncodeToString(hotVer.Extra), SafeUtxoStateUnspent, sequence, hotHash)
	hot.KernelAssetId = hotVer.Asset.String()
	g.processSafeOutput(ctx, hot)
	r.NoError(g.handleActionsQueue(ctx))
	balance := g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("0", balance.Amount.String())
	r.Equal("0", balance.ReservedAmount.String())

	// Untrusted requests must not move the hot balance into custody.
	sequence++
	unauthorizedTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(SOLAssetId)))
	unauthorizedTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
	unauthorizedTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, EncodeCustodianTransferMemo(USDTAssetId, "8")))
	unauthorizedTx.Outputs = append(unauthorizedTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString("0.00000001"), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
	unauthorizedVer := unauthorizedTx.AsVersioned()
	unauthorizedHash := unauthorizedVer.PayloadHash().String()
	r.NoError(g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", unauthorizedHash), base64.RawURLEncoding.EncodeToString(unauthorizedVer.Marshal())))
	unauthorized := testBuildOutput(g, r, SOLAssetId, "0.00000001", hex.EncodeToString(unauthorizedVer.Extra), SafeUtxoStateUnspent, sequence, unauthorizedHash)
	unauthorized.KernelAssetId = unauthorizedVer.Asset.String()
	unauthorized.Senders = []string{g.GetMembers()[0]}
	g.processSafeOutput(ctx, unauthorized)
	r.NoError(g.handleActionsQueue(ctx))
	transfers, err := g.ListPendingCustodianTransfers(ctx, 0)
	r.NoError(err)
	r.Empty(transfers)
	txs, _, err := g.store.ListTransactions(ctx, TransactionStateInitial, 0)
	r.NoError(err)
	r.Empty(txs)

	sequence++
	requestTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(SOLAssetId)))
	requestTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
	requestTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, EncodeCustodianTransferMemo(USDTAssetId, "8")))
	requestTx.Outputs = append(requestTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString("0.00000001"), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
	requestVer := requestTx.AsVersioned()
	requestHash := requestVer.PayloadHash().String()
	r.NoError(g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", requestHash), base64.RawURLEncoding.EncodeToString(requestVer.Marshal())))
	request := testBuildOutput(g, r, SOLAssetId, "0.00000001", hex.EncodeToString(requestVer.Extra), SafeUtxoStateUnspent, sequence, requestHash)
	request.KernelAssetId = requestVer.Asset.String()
	g.processSafeOutput(ctx, request)
	r.NoError(g.handleActionsQueue(ctx))
	transfers, err = g.ListPendingCustodianTransfers(ctx, 0)
	r.NoError(err)
	r.Len(transfers, 1)
	transfer := transfers[0]
	r.Equal(request.OutputId, transfer.ActionId)
	r.Equal("8", transfer.Amount.String())
	r.Equal(g.custodianAddress, transfer.Address)
	tx, err := g.store.ReadTransactionByTraceId(ctx, transfer.TraceId)
	r.NoError(err)
	r.NotNil(tx)
	r.ElementsMatch(g.custodianMembers, tx.Receivers)
	r.Equal(g.custodianThreshold, tx.Threshold)
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("0", balance.Amount.String())
	r.Equal("0", balance.ReservedAmount.String())

	// Even an authorized observer cannot credit the balance before this node
	// observes the transfer snapshot; the confirmation blocks later actions.
	confirmationMemo := EncodeCustodianTransferConfirmationMemo(transfer.TraceId)
	sequence++
	unauthorizedConfirmationTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(SOLAssetId)))
	unauthorizedConfirmationTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
	unauthorizedConfirmationTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, confirmationMemo))
	unauthorizedConfirmationTx.Outputs = append(unauthorizedConfirmationTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString("0.00000001"), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
	unauthorizedConfirmationVer := unauthorizedConfirmationTx.AsVersioned()
	unauthorizedConfirmationHash := unauthorizedConfirmationVer.PayloadHash().String()
	r.NoError(g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", unauthorizedConfirmationHash), base64.RawURLEncoding.EncodeToString(unauthorizedConfirmationVer.Marshal())))
	unauthorizedConfirmation := testBuildOutput(g, r, SOLAssetId, "0.00000001", hex.EncodeToString(unauthorizedConfirmationVer.Extra), SafeUtxoStateUnspent, sequence, unauthorizedConfirmationHash)
	unauthorizedConfirmation.KernelAssetId = unauthorizedConfirmationVer.Asset.String()
	unauthorizedConfirmation.Senders = []string{g.GetMembers()[0]}
	g.processSafeOutput(ctx, unauthorizedConfirmation)
	r.NoError(g.handleActionsQueue(ctx))
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("0", balance.Amount.String())
	r.Equal("0", balance.ReservedAmount.String())

	sequence++
	confirmationTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(SOLAssetId)))
	confirmationTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
	confirmationTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, confirmationMemo))
	confirmationTx.Outputs = append(confirmationTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString("0.00000001"), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
	confirmationVer := confirmationTx.AsVersioned()
	confirmationHash := confirmationVer.PayloadHash().String()
	r.NoError(g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", confirmationHash), base64.RawURLEncoding.EncodeToString(confirmationVer.Marshal())))
	confirmation := testBuildOutput(g, r, SOLAssetId, "0.00000001", hex.EncodeToString(confirmationVer.Extra), SafeUtxoStateUnspent, sequence, confirmationHash)
	confirmation.KernelAssetId = confirmationVer.Asset.String()
	g.processSafeOutput(ctx, confirmation)
	r.NoError(g.handleActionsQueue(ctx))
	action, err := g.store.ReadAction(ctx, confirmation.OutputId)
	r.NoError(err)
	r.Equal(ActionStateInitial, action.ActionState)
	r.NotNil(g.signTransaction(ctx, tx))
	r.NoError(g.handleActionsQueue(ctx))
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("0", balance.Amount.String())
	r.Equal("0", balance.ReservedAmount.String())
	r.NoError(g.store.FinishTransaction(ctx, tx.TraceId))
	r.NoError(g.handleActionsQueue(ctx))
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("8", balance.Amount.String())
	r.Equal("0", balance.ReservedAmount.String())
	transfers, err = g.ListPendingCustodianTransfers(ctx, 0)
	r.NoError(err)
	r.Empty(transfers)
	stored, err := g.store.ReadCustodianTransferByTraceId(ctx, transfer.TraceId)
	r.NoError(err)
	r.Equal(CustodianTransferStateDone, stored.State)

	sequence++
	duplicateConfirmationTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(SOLAssetId)))
	duplicateConfirmationTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
	duplicateConfirmationTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, confirmationMemo))
	duplicateConfirmationTx.Outputs = append(duplicateConfirmationTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString("0.00000001"), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
	duplicateConfirmationVer := duplicateConfirmationTx.AsVersioned()
	duplicateConfirmationHash := duplicateConfirmationVer.PayloadHash().String()
	r.NoError(g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", duplicateConfirmationHash), base64.RawURLEncoding.EncodeToString(duplicateConfirmationVer.Marshal())))
	duplicateConfirmation := testBuildOutput(g, r, SOLAssetId, "0.00000001", hex.EncodeToString(duplicateConfirmationVer.Extra), SafeUtxoStateUnspent, sequence, duplicateConfirmationHash)
	duplicateConfirmation.KernelAssetId = duplicateConfirmationVer.Asset.String()
	g.processSafeOutput(ctx, duplicateConfirmation)
	r.NoError(g.handleActionsQueue(ctx))
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("8", balance.Amount.String())
	r.Equal("0", balance.ReservedAmount.String())

	// A custody transfer may spend only internal funds, not count the external
	// balance and recursively request a refill to send the same funds back out.
	sequence++
	unfundedTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(SOLAssetId)))
	unfundedTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
	unfundedTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, EncodeCustodianTransferMemo(USDTAssetId, "3")))
	unfundedTx.Outputs = append(unfundedTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString("0.00000001"), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
	unfundedVer := unfundedTx.AsVersioned()
	unfundedHash := unfundedVer.PayloadHash().String()
	r.NoError(g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", unfundedHash), base64.RawURLEncoding.EncodeToString(unfundedVer.Marshal())))
	unfunded := testBuildOutput(g, r, SOLAssetId, "0.00000001", hex.EncodeToString(unfundedVer.Extra), SafeUtxoStateUnspent, sequence, unfundedHash)
	unfunded.KernelAssetId = unfundedVer.Asset.String()
	g.processSafeOutput(ctx, unfunded)
	r.NoError(g.handleActionsQueue(ctx))
	failed, err := g.store.ReadCustodianTransferByRequestId(ctx, unfunded.OutputId)
	r.NoError(err)
	r.NotNil(failed)
	r.Equal(CustodianTransferStateFailed, failed.State)
	funding, err := g.ListFundingRequests(ctx, 0)
	r.NoError(err)
	r.Empty(funding)

	// Fragment the hot balance into 36 outputs totaling 2. The first payout
	// requires compaction before requesting 5; the second then requests 2.
	for i := 0; i < OutputsBatchSize; i++ {
		amount := "0.05"
		if i == OutputsBatchSize-1 {
			amount = "0.25"
		}
		sequence++
		fragmentTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(USDTAssetId)))
		fragmentTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
		fragmentTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, nil))
		fragmentTx.Outputs = append(fragmentTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString(amount), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
		fragmentVer := fragmentTx.AsVersioned()
		fragmentHash := fragmentVer.PayloadHash().String()
		r.NoError(g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", fragmentHash), base64.RawURLEncoding.EncodeToString(fragmentVer.Marshal())))
		out := testBuildOutput(g, r, USDTAssetId, amount, hex.EncodeToString(fragmentVer.Extra), SafeUtxoStateUnspent, sequence, fragmentHash)
		out.KernelAssetId = fragmentVer.Asset.String()
		g.processSafeOutput(ctx, out)
		r.NoError(g.handleActionsQueue(ctx))
	}
	sequence++
	payoutInputTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(SOLAssetId)))
	payoutInputTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
	payoutInputTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, []byte("custodian-test-pay")))
	payoutInputTx.Outputs = append(payoutInputTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString("0.00000001"), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
	payoutInputVer := payoutInputTx.AsVersioned()
	payoutInputHash := payoutInputVer.PayloadHash().String()
	r.NoError(g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", payoutInputHash), base64.RawURLEncoding.EncodeToString(payoutInputVer.Marshal())))
	payout := testBuildOutput(g, r, SOLAssetId, "0.00000001", hex.EncodeToString(payoutInputVer.Extra), SafeUtxoStateUnspent, sequence, payoutInputHash)
	payout.KernelAssetId = payoutInputVer.Asset.String()
	g.processSafeOutput(ctx, payout)
	r.NoError(g.handleActionsQueue(ctx))
	action, err = g.store.ReadAction(ctx, payout.OutputId)
	r.NoError(err)
	r.Equal(ActionStateRestorable, action.ActionState)
	funding, err = g.ListFundingRequests(ctx, 0)
	r.NoError(err)
	r.Empty(funding)
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("8", balance.Amount.String())
	r.Equal("0", balance.ReservedAmount.String())
	spare := testHandleCompactionTransaction(ctx, r, g, payout.TransactionHash)
	r.Equal("2", spare.Amount.String())
	sequence = spare.Sequence
	g.processSafeOutput(ctx, spare)
	r.NoError(g.handleActionsQueue(ctx))
	action, err = g.store.ReadAction(ctx, payout.OutputId)
	r.NoError(err)
	r.Equal(ActionStateInitial, action.ActionState)
	r.Equal(spare.Sequence, action.restoreSequence)
	r.NoError(g.handleActionsQueue(ctx))
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("8", balance.Amount.String())
	r.Equal("5", balance.ReservedAmount.String())
	funding, err = g.ListFundingRequests(ctx, 0)
	r.NoError(err)
	r.Len(funding, 1)
	need := funding[0]
	r.Equal("5", need.Amount.String())
	r.Equal(USDTAssetId, need.AssetId)
	r.Equal(payout.OutputId, need.ActionId)
	r.Equal(g.custodianAddress, need.CustodianAddress)
	returnAddress, _, err := NewMixAddress(ctx, g.GetMembers(), byte(g.GetThreshold()))
	r.NoError(err)
	r.Equal(returnAddress.String(), need.ReturnAddress)
	requestId, ok := DecodeFundingReturnMemo(need.ReturnMemo)
	r.True(ok)
	r.Equal(need.TraceId, requestId)
	locked, err := g.store.ReadOutputById(ctx, spare.OutputId)
	r.NoError(err)
	r.Equal(SafeUtxoStateLocked, locked.State)
	r.Equal(payout.OutputId, locked.ReservedBy)
	r.Empty(g.ListOutputsForAsset(ctx, g.GroupId, USDTAssetId, 0, sequence, SafeUtxoStateUnspent, 0))
	action, err = g.store.ReadAction(ctx, payout.OutputId)
	r.NoError(err)
	r.Equal(ActionStateRestorable, action.ActionState)
	r.NoError(g.handleActionsQueue(ctx))
	funding, err = g.ListFundingRequests(ctx, 0)
	r.NoError(err)
	r.Len(funding, 1)
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("8", balance.Amount.String())
	r.Equal("5", balance.ReservedAmount.String())

	// Restart while waiting: reservations and the original request ID persist.
	r.NoError(g.store.Close())
	store, err = OpenSQLite3Store(path)
	r.NoError(err)
	rebuilt, err := BuildGroup(ctx, store, &conf)
	r.NoError(err)
	*g = *rebuilt
	g.EnableDebug()
	g.AttachWorker(g.GroupId, &custodianFlowWorker{})
	funding, err = g.ListFundingRequests(ctx, 0)
	r.NoError(err)
	r.Len(funding, 1)
	r.Equal(need.TraceId, funding[0].TraceId)
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("8", balance.Amount.String())
	r.Equal("5", balance.ReservedAmount.String())

	// Invalid returns cannot complete the waiting request or consume reservations.
	for _, kind := range []string{"asset", "amount", "sender", "threshold", "app", "request", "sequence", "kernel amount"} {
		t.Run("reject return "+kind, func(t *testing.T) {
			asset, amount, memo := USDTAssetId, "5", need.ReturnMemo
			senders, threshold := g.custodianMembers, g.custodianThreshold
			switch kind {
			case "asset":
				asset = SOLAssetId
			case "amount", "kernel amount":
				amount = "4"
			case "sender":
				senders = []string{testSender, g.GetMembers()[0]}
			case "threshold":
				threshold = 1
			case "request":
				memo = EncodeFundingReturnMemo(UniqueId(need.TraceId, "unknown"))
			}
			sequence++
			returnTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(asset)))
			returnTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
			returnTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, memo))
			returnTx.Outputs = append(returnTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString(amount), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
			returnVer := returnTx.AsVersioned()
			returnHash := returnVer.PayloadHash().String()
			require.NoError(t, g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", returnHash), base64.RawURLEncoding.EncodeToString(returnVer.Marshal())))
			out := testBuildOutput(g, require.New(t), asset, amount, hex.EncodeToString(returnVer.Extra), SafeUtxoStateUnspent, sequence, returnHash)
			out.KernelAssetId = returnVer.Asset.String()
			out.Senders = append([]string(nil), senders...)
			out.SendersThreshold = int64(threshold)
			switch kind {
			case "app":
				out.AppId = UniqueId(g.GroupId, "other app")
			case "sequence":
				out.Sequence = need.Sequence
			case "kernel amount":
				out.Amount = decimal.NewFromInt(5)
			}
			matched, err := g.checkFundingReturn(ctx, &Action{UnifiedOutput: *out})
			require.NoError(t, err)
			require.Nil(t, matched)
			balance := g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
			require.Equal(t, "8", balance.Amount.String())
			require.Equal(t, "5", balance.ReservedAmount.String())
			waiting, err := g.store.ReadLiquidityRequest(ctx, need.TraceId)
			require.NoError(t, err)
			require.Equal(t, LiquidityRequestStateWaiting, waiting.State)
		})
	}

	sequence++
	returnedTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(USDTAssetId)))
	returnedTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
	returnedTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, need.ReturnMemo))
	returnedTx.Outputs = append(returnedTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString("5"), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
	returnedVer := returnedTx.AsVersioned()
	returnedHash := returnedVer.PayloadHash().String()
	r.NoError(g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", returnedHash), base64.RawURLEncoding.EncodeToString(returnedVer.Marshal())))
	returned := testBuildOutput(g, r, USDTAssetId, "5", hex.EncodeToString(returnedVer.Extra), SafeUtxoStateUnspent, sequence, returnedHash)
	returned.KernelAssetId = returnedVer.Asset.String()
	returned.Senders = append([]string(nil), g.custodianMembers...)
	returned.SendersThreshold = int64(g.custodianThreshold)
	g.processSafeOutput(ctx, returned)
	r.NoError(g.handleActionsQueue(ctx))
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("3", balance.Amount.String())
	r.Equal("0", balance.ReservedAmount.String())
	action, err = g.store.ReadAction(ctx, payout.OutputId)
	r.NoError(err)
	r.Equal(ActionStateInitial, action.ActionState)
	r.Equal(returned.Sequence, action.restoreSequence)
	waiting, err := g.store.ReadLiquidityRequest(ctx, need.TraceId)
	r.NoError(err)
	r.Equal(LiquidityRequestStateDone, waiting.State)
	r.Equal(returned.OutputId, waiting.ReturnOutputId)
	returnedStored, err := g.store.ReadOutputById(ctx, returned.OutputId)
	r.NoError(err)
	r.Equal(SafeUtxoStateLocked, returnedStored.State)
	r.Equal(payout.OutputId, returnedStored.ReservedBy)
	// Replaying after the first return can build payout 0, but payout 1 still
	// needs its own refill. Neither transaction may be persisted prematurely.
	r.NoError(g.handleActionsQueue(ctx))
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("3", balance.Amount.String())
	r.Equal("2", balance.ReservedAmount.String())
	funding, err = g.ListFundingRequests(ctx, 0)
	r.NoError(err)
	r.Len(funding, 1)
	secondNeed := funding[0]
	r.NotEqual(need.TraceId, secondNeed.TraceId)
	r.Equal(payout.OutputId, secondNeed.ActionId)
	r.Equal(USDTAssetId, secondNeed.AssetId)
	r.Equal("2", secondNeed.Amount.String())
	action, err = g.store.ReadAction(ctx, payout.OutputId)
	r.NoError(err)
	r.Equal(ActionStateRestorable, action.ActionState)
	txs, _, err = g.store.ListTransactions(ctx, TransactionStateInitial, 0)
	r.NoError(err)
	r.Empty(txs)
	for _, id := range []string{spare.OutputId, returned.OutputId} {
		out, err := g.store.ReadOutputById(ctx, id)
		r.NoError(err)
		r.Equal(SafeUtxoStateLocked, out.State)
		r.Equal(payout.OutputId, out.ReservedBy)
	}
	g.processSafeOutput(ctx, returned)
	r.NoError(g.handleActionsQueue(ctx))
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("3", balance.Amount.String())
	r.Equal("2", balance.ReservedAmount.String())
	funding, err = g.ListFundingRequests(ctx, 0)
	r.NoError(err)
	r.Len(funding, 1)
	r.Equal(secondNeed.TraceId, funding[0].TraceId)

	sequence++
	secondReturnTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(USDTAssetId)))
	secondReturnTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
	secondReturnTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, secondNeed.ReturnMemo))
	secondReturnTx.Outputs = append(secondReturnTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString("2"), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
	secondReturnVer := secondReturnTx.AsVersioned()
	secondReturnHash := secondReturnVer.PayloadHash().String()
	r.NoError(g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", secondReturnHash), base64.RawURLEncoding.EncodeToString(secondReturnVer.Marshal())))
	secondReturn := testBuildOutput(g, r, USDTAssetId, "2", hex.EncodeToString(secondReturnVer.Extra), SafeUtxoStateUnspent, sequence, secondReturnHash)
	secondReturn.KernelAssetId = secondReturnVer.Asset.String()
	secondReturn.Senders = append([]string(nil), g.custodianMembers...)
	secondReturn.SendersThreshold = int64(g.custodianThreshold)
	g.processSafeOutput(ctx, secondReturn)
	r.NoError(g.handleActionsQueue(ctx))
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("1", balance.Amount.String())
	r.Equal("0", balance.ReservedAmount.String())
	action, err = g.store.ReadAction(ctx, payout.OutputId)
	r.NoError(err)
	r.Equal(ActionStateInitial, action.ActionState)
	r.Equal(secondReturn.Sequence, action.restoreSequence)
	waiting, err = g.store.ReadLiquidityRequest(ctx, secondNeed.TraceId)
	r.NoError(err)
	r.Equal(LiquidityRequestStateDone, waiting.State)
	r.Equal(secondReturn.OutputId, waiting.ReturnOutputId)
	r.NoError(g.handleActionsQueue(ctx))
	action, err = g.store.ReadAction(ctx, payout.OutputId)
	r.NoError(err)
	r.Equal(ActionStateDone, action.ActionState)
	txs, _, err = g.store.ListTransactions(ctx, TransactionStateInitial, 0)
	r.NoError(err)
	r.Len(txs, 2)
	for i, amount := range []string{"7", "2"} {
		payoutTx, err := g.store.ReadTransactionByTraceId(ctx, UniqueId(payout.OutputId, fmt.Sprintf("payout:%d", i)))
		r.NoError(err)
		r.NotNil(payoutTx)
		r.Equal(amount, payoutTx.Amount)
		r.Equal(secondReturn.Sequence, payoutTx.Sequence)
		inputs := g.ListOutputsForTransaction(ctx, payoutTx.TraceId, payoutTx.Sequence)
		var ids []string
		for _, input := range inputs {
			ids = append(ids, input.OutputId)
			r.Equal(SafeUtxoStateAssigned, input.State)
			r.Empty(input.ReservedBy)
		}
		if i == 0 {
			r.ElementsMatch([]string{spare.OutputId, returned.OutputId}, ids)
		} else {
			r.Equal([]string{secondReturn.OutputId}, ids)
		}
		r.NotNil(g.signTransaction(ctx, payoutTx))
		r.NoError(g.store.FinishTransaction(ctx, payoutTx.TraceId))
	}
	for _, id := range []string{spare.OutputId, returned.OutputId, secondReturn.OutputId} {
		out, err := g.store.ReadOutputById(ctx, id)
		r.NoError(err)
		r.Equal(SafeUtxoStateSpent, out.State)
	}
	// Re-delivering the same chain outputs is idempotent after both payouts.
	g.processSafeOutput(ctx, returned)
	g.processSafeOutput(ctx, secondReturn)
	r.NoError(g.handleActionsQueue(ctx))
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("1", balance.Amount.String())
	r.Equal("0", balance.ReservedAmount.String())
	funding, err = g.ListFundingRequests(ctx, 0)
	r.NoError(err)
	r.Empty(funding)
	txs, _, err = g.store.ListTransactions(ctx, TransactionStateSnapshot, 0)
	r.NoError(err)
	r.Len(txs, 4) // Custody transfer, compaction, and two payouts.
}

func TestMTGCustodianCompaction(t *testing.T) {
	r := require.New(t)
	ctx := util.EnableTestEnvironment(context.Background())
	data, err := os.ReadFile("example.toml")
	r.NoError(err)
	var conf Configuration
	r.NoError(toml.Unmarshal(data, &conf))
	conf.StoreDir = t.TempDir()
	conf.GroupSize = 1
	conf.Custodian = CustodianConfiguration{
		MixAddress:     mixin.RequireNewMixAddress([]string{testSender, "194ac88f-4671-3976-b60a-09064f1811e8"}, 2).String(),
		ConversationId: "294ac88f-4671-3976-b60a-09064f1811e8",
		Requesters:     []string{testSender},
	}
	path := filepath.Join(conf.StoreDir, "mtg.sqlite3")
	legacy, err := sql.Open("sqlite3", path)
	r.NoError(err)
	_, err = legacy.Exec(strings.Replace(SCHEMA, "  reserved_by          VARCHAR NOT NULL,\n", "", 1))
	r.NoError(err)
	r.NoError(legacy.Close())
	store, err := OpenSQLite3Store(path)
	r.NoError(err)
	g, err := BuildGroup(ctx, store, &conf)
	r.NoError(err)
	g.EnableDebug()
	g.AttachWorker(g.GroupId, &custodianFlowWorker{})
	sequence := conf.Genesis.Epoch
	t.Cleanup(func() { r.NoError(g.store.Close()) })

	for i := 0; i < OutputsBatchSize+1; i++ {
		amount := "0.1"
		if i == OutputsBatchSize {
			amount = "1"
		}
		sequence++
		inputTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(USDTAssetId)))
		inputTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
		inputTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, nil))
		inputTx.Outputs = append(inputTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString(amount), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
		inputVer := inputTx.AsVersioned()
		inputHash := inputVer.PayloadHash().String()
		r.NoError(g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", inputHash), base64.RawURLEncoding.EncodeToString(inputVer.Marshal())))
		out := testBuildOutput(g, r, USDTAssetId, amount, hex.EncodeToString(inputVer.Extra), SafeUtxoStateUnspent, sequence, inputHash)
		out.KernelAssetId = inputVer.Asset.String()
		r.NoError(g.store.WriteAction(ctx, out, ActionStateDone))
	}
	sequence++
	requestTx := common.NewTransactionV5(crypto.Sha256Hash([]byte(SOLAssetId)))
	requestTx.AddInput(crypto.Sha256Hash([]byte(fmt.Sprintf("custodian-input:%d", sequence))), 0)
	requestTx.Extra = []byte(EncodeMixinExtraBase64(g.GroupId, EncodeCustodianTransferMemo(USDTAssetId, "4.6")))
	requestTx.Outputs = append(requestTx.Outputs, &common.Output{Type: common.OutputTypeScript, Amount: common.NewIntegerFromString("0.00000001"), Script: common.NewThresholdScript(byte(g.GetThreshold()))})
	requestVer := requestTx.AsVersioned()
	requestHash := requestVer.PayloadHash().String()
	r.NoError(g.store.WriteCache(ctx, fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", requestHash), base64.RawURLEncoding.EncodeToString(requestVer.Marshal())))
	request := testBuildOutput(g, r, SOLAssetId, "0.00000001", hex.EncodeToString(requestVer.Extra), SafeUtxoStateUnspent, sequence, requestHash)
	request.KernelAssetId = requestVer.Asset.String()
	g.processSafeOutput(ctx, request)
	r.NoError(g.handleActionsQueue(ctx))
	pending, err := g.ListPendingCustodianTransfers(ctx, 0)
	r.NoError(err)
	r.Empty(pending)
	action, err := g.store.ReadAction(ctx, request.OutputId)
	r.NoError(err)
	r.Equal(ActionStateRestorable, action.ActionState)
	balance := g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("0", balance.Amount.String())
	r.Equal("0", balance.ReservedAmount.String())
	compacted := testHandleCompactionTransaction(ctx, r, g, request.TransactionHash)
	g.processSafeOutput(ctx, compacted)
	r.NoError(g.handleActionsQueue(ctx))
	action, err = g.store.ReadAction(ctx, request.OutputId)
	r.NoError(err)
	r.Equal(ActionStateInitial, action.ActionState)
	r.Equal(compacted.Sequence, action.restoreSequence)
	r.NoError(g.handleActionsQueue(ctx))
	pending, err = g.ListPendingCustodianTransfers(ctx, 0)
	r.NoError(err)
	r.Len(pending, 1)
	r.Equal(UniqueId(request.OutputId, "custodian-transfer"), pending[0].TraceId)
	r.Equal("4.6", pending[0].Amount.String())
	r.Equal(compacted.Sequence, pending[0].Sequence)
	tx, err := g.store.ReadTransactionByTraceId(ctx, pending[0].TraceId)
	r.NoError(err)
	r.NotNil(tx)
	r.False(tx.compaction)
	inputs := g.ListOutputsForTransaction(ctx, tx.TraceId, tx.Sequence)
	r.Len(inputs, 2)
	balance = g.ReadExternalBalance(ctx, g.GroupId, USDTAssetId)
	r.Equal("0", balance.Amount.String())
	r.Equal("0", balance.ReservedAmount.String())
	funding, err := g.ListFundingRequests(ctx, 0)
	r.NoError(err)
	r.Empty(funding)
}
