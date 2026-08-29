package mtg

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/util"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

type coverageRow struct {
	err error
}

func (r coverageRow) Scan(_ ...any) error {
	return r.err
}

type coverageCloser struct {
	err error
}

func (c coverageCloser) Close() error {
	return c.err
}

var _ Row = coverageRow{}
var _ io.Closer = coverageCloser{}

func TestCoverageGroupConfigurationAndAccessors(t *testing.T) {
	req := require.New(t)
	ctx, node := testBuildGroup(req)
	grp := node.Group
	defer teardownTestDatabase(grp.store)

	req.Equal(0, grp.Index())
	req.False(grp.Synced(ctx))
	req.NoError(grp.store.WriteProperty(ctx, groupBootSynced, "1"))
	req.True(grp.Synced(ctx))
	grp.SetKernelRPC("http://kernel.invalid")
	req.Equal("http://kernel.invalid", grp.kernelRPC)

	members := grp.GetMembers()
	req.Equal(grp.rawMembers, members)
	members[0] = "mutated"
	req.NotEqual(members, grp.GetMembers())

	copyGroup := *grp
	copyGroup.index = -1
	req.Panics(func() { copyGroup.Index() })
	copyGroup = *grp
	copyGroup.rawMembers = append([]string(nil), grp.rawMembers...)
	copyGroup.rawMembers[0], copyGroup.rawMembers[1] = copyGroup.rawMembers[1], copyGroup.rawMembers[0]
	copyGroup.debug = true
	req.Panics(func() { copyGroup.GetMembers() })

	appID := uuid.Must(uuid.NewV4()).String()
	worker := &Node{Group: grp}
	grp.AttachWorker(appID, worker)
	req.Equal(worker, grp.FindWorker(appID))
	req.Panics(func() { grp.AttachWorker(appID, worker) })
	entry := DepositEntry{Destination: "destination", Tag: "tag"}
	grp.RegisterDepositEntry(appID, entry)
	req.Equal(appID, grp.FindAppByEntry(entry.UniqueKey()))
	req.Panics(func() { grp.RegisterDepositEntry(appID, entry) })
	req.Panics(func() { grp.RegisterDepositEntry(uuid.Must(uuid.NewV4()).String(), DepositEntry{Destination: "other"}) })

	req.NoError(grp.signTransactions(ctx))
	req.NoError(grp.publishTransactions(ctx))
	req.Empty(grp.ListUnconfirmedWithdrawalTransactions(ctx, 1))
	req.Empty(grp.ListConfirmedWithdrawalTransactionsAfter(ctx, time.Time{}, 1))

	var invalid Configuration
	invalid.Genesis.Threshold = 1
	_, err := BuildGroup(ctx, nil, &invalid)
	req.ErrorContains(err, "invalid group threshold")
	invalid.Genesis.Members = []string{uuid.Must(uuid.NewV4()).String()}
	invalid.App.AppId = uuid.Must(uuid.NewV4()).String()
	_, err = BuildGroup(ctx, nil, &invalid)
	req.ErrorContains(err, "not belongs to the group")

	confA := &Configuration{}
	confA.Genesis.Members = []string{"b", "a"}
	confA.Genesis.Threshold = 1
	confA.Genesis.Epoch = 9
	confB := &Configuration{}
	confB.Genesis.Members = []string{"a", "b"}
	confB.Genesis.Threshold = 1
	confB.Genesis.Epoch = 9
	req.Equal(generateGenesisId(confA), generateGenesisId(confB))
	req.Equal([]string{"a", "b"}, confA.Genesis.Members)
}

func TestCoverageEncodingAndTransactionValidation(t *testing.T) {
	req := require.New(t)
	appID := uuid.Must(uuid.NewV4()).String()
	opponentID := uuid.Must(uuid.NewV4()).String()
	actionID := uuid.Must(uuid.NewV4()).String()
	assetID := uuid.Must(uuid.NewV4()).String()
	consumedID := uuid.Must(uuid.NewV4()).String()
	reference := crypto.Sha256Hash([]byte("reference"))
	tx := &Transaction{
		TraceId:        uuid.Must(uuid.NewV4()).String(),
		AppId:          appID,
		OpponentAppId:  opponentID,
		ActionId:       actionID,
		State:          TransactionStateInitial,
		AssetId:        assetID,
		Receivers:      []string{uuid.Must(uuid.NewV4()).String()},
		Threshold:      1,
		Amount:         "1.00000000",
		Memo:           "memo",
		Sequence:       42,
		references:     []crypto.Hash{reference},
		storageTraceId: uuid.Must(uuid.NewV4()).String(),
		consumedIds:    []string{consumedID},
	}
	raw := tx.Serialize()
	decoded, err := Deserialize(raw)
	req.NoError(err)
	req.True(tx.Equal(decoded))
	for i := 0; i < len(raw); i++ {
		_, err := Deserialize(raw[:i])
		req.Error(err, "prefix length %d", i)
	}

	withdrawal := *tx
	withdrawal.storageTraceId = ""
	withdrawal.Receivers = nil
	withdrawal.Threshold = 0
	withdrawal.Destination = sql.NullString{Valid: true, String: "destination"}
	withdrawal.Tag = sql.NullString{Valid: true, String: "tag"}
	withdrawalRaw := withdrawal.Serialize()
	decodedWithdrawal, err := Deserialize(withdrawalRaw)
	req.NoError(err)
	req.True(withdrawal.Equal(decodedWithdrawal))

	batch := SerializeTransactions([]*Transaction{tx, &withdrawal})
	transactions, err := DeserializeTransactions(batch)
	req.NoError(err)
	req.Len(transactions, 2)
	for i := 0; i < len(batch); i++ {
		_, err := DeserializeTransactions(batch[:i])
		if i != 1 { // a zero transaction count is intentionally accepted
			req.Error(err, "batch prefix length %d", i)
		}
	}
	empty, err := DeserializeTransactions([]byte{0})
	req.NoError(err)
	req.Nil(empty)

	req.Panics(func() { writeByte(common.NewEncoder(), 201) })
	req.Panics(func() { writeUuid(common.NewEncoder(), "invalid") })
	req.Panics(func() { writeReferences(common.NewEncoder(), []crypto.Hash{{}}) })
	req.Panics(func() { writeConsumed(common.NewEncoder(), []*UnifiedOutput{{}}, nil) })
	req.Panics(func() { (&Transaction{TraceId: "missing-consumed"}).getConsumedString() })
	req.Panics(func() {
		(&Transaction{TraceId: "mismatch", consumed: []*UnifiedOutput{{}}, consumedIds: []string{consumedID, appID}}).getConsumedString()
	})

	action := &Action{UnifiedOutput: UnifiedOutput{OutputId: actionID, AppId: appID, Sequence: 42}}
	req.NoError(tx.check(context.Background(), action))
	mutations := []func(*Transaction){
		func(v *Transaction) { v.AppId = uuid.Must(uuid.NewV4()).String() },
		func(v *Transaction) { v.references = []crypto.Hash{reference, reference, reference} },
		func(v *Transaction) { v.references = []crypto.Hash{{}} },
		func(v *Transaction) { v.Threshold = 0 },
		func(v *Transaction) { v.Receivers = []string{"invalid"} },
		func(v *Transaction) { v.Amount = "0.000000001" },
		func(v *Transaction) { v.Memo = strings.Repeat("x", common.ExtraSizeGeneralLimit) },
	}
	for _, mutate := range mutations {
		candidate := *tx
		candidate.Receivers = append([]string(nil), tx.Receivers...)
		candidate.references = append([]crypto.Hash(nil), tx.references...)
		mutate(&candidate)
		req.Error(candidate.check(context.Background(), action))
	}

	req.Equal(tx.TraceId, tx.RequestID())
	tx.requestId = sql.NullString{Valid: true, String: "request"}
	req.Equal("request", tx.RequestID())
	req.Equal(common.NewIntegerFromString(common.ExtraStoragePriceStep), getStorageTransactionAmount(nil))
	req.Equal(common.NewIntegerFromString(common.ExtraStoragePriceStep).Mul(2), getStorageTransactionAmount(make([]byte, common.ExtraSizeStorageStep)))
	checkAmountPrecision("1.00000001")
	req.Panics(func() { checkAmountPrecision("0.000000001") })

	a := &Action{restoreSequence: 1}
	req.True(a.Restored())
	a.restoreSequence = 0
	req.False(a.Restored())
	a.TestAttachActionToGroup(&Group{})
	req.NotNil(a.consumed)
	replayCheck(a, []*Transaction{tx}, []*Transaction{tx}, "asset", "asset")
	req.Panics(func() { replayCheck(a, nil, nil, "one", "two") })
	req.Panics(func() { replayCheck(a, []*Transaction{tx}, nil, "asset", "asset") })
}

func TestCoverageUtilitiesAndCachedReads(t *testing.T) {
	req := require.New(t)
	ctx, node := testBuildGroup(req)
	grp := node.Group
	defer teardownTestDatabase(grp.store)

	for _, message := range []string{
		"EOF",
		"context deadline exceeded",
		"connection reset by peer",
		"Client.Timeout exceeded",
		"Bad Gateway",
		"Internal Server Error",
		"invalid character '<' looking for beginning of value",
		"TLS handshake timeout",
	} {
		req.True(CheckRetryableError(errors.New(message)))
	}
	req.False(CheckRetryableError(nil))
	req.False(CheckRetryableError(errors.New("permanent")))

	testCtx := util.EnableTestEnvironment(context.Background())
	members := []string{"member-one", "member-two"}
	address, uuidMembers, err := NewMixAddress(testCtx, members, 2)
	req.NoError(err)
	req.True(uuidMembers)
	req.Equal(uint8(2), address.Threshold)
	req.Panics(func() { NewMixAddress(testCtx, nil, 1) })
	req.Panics(func() { NewMixAddress(testCtx, []string{"one"}, 0) })
	_, _, err = NewMixAddress(context.Background(), []string{"invalid"}, 1)
	req.Error(err)

	appID := uuid.Must(uuid.NewV4()).String()
	extra := []byte("payload")
	encoded := EncodeMixinExtraBase64(appID, extra)
	decodedID, decodedExtra := DecodeMixinExtraBase64(encoded)
	req.Equal(appID, decodedID)
	req.Equal(extra, decodedExtra)
	decodedID, decodedExtra = DecodeMixinExtraHEX(hex.EncodeToString([]byte(encoded)))
	req.Equal(appID, decodedID)
	req.Equal(extra, decodedExtra)
	req.Equal("", first(DecodeMixinExtraHEX("zz")))
	req.Equal("", first(DecodeMixinExtraBase64("invalid")))
	req.Equal("", first(DecodeMixinExtraBase64(base64.RawURLEncoding.EncodeToString([]byte("short")))))
	req.Panics(func() { EncodeMixinExtraBase64("invalid", nil) })

	req.Empty(mustReadMTGCache(t, grp.store, ctx, "missing"))
	req.NoError(grp.store.WriteCache(ctx, "current", "value"))
	req.Equal("value", mustReadMTGCache(t, grp.store, ctx, "current"))
	req.Error(grp.store.WriteCache(ctx, "current", "duplicate"))
	_, err = grp.store.db.Exec("INSERT INTO caches (key,value,created_at) VALUES (?,?,?)", "expired", "old", time.Now().Add(-cacheTTL-time.Hour))
	req.NoError(err)
	req.Empty(mustReadMTGCache(t, grp.store, ctx, "expired"))

	deposit := &SafeDepositView{DepositHash: "hash", DepositIndex: 7, Destination: "destination", Tag: "tag"}
	b, err := json.Marshal(deposit)
	req.NoError(err)
	depositID := uuid.Must(uuid.NewV4()).String()
	req.NoError(grp.store.WriteCache(ctx, "readOutputDepositUntilSufficient("+depositID+")", string(b)))
	cachedDeposit, err := grp.readOutputDepositUntilSufficient(ctx, depositID)
	req.NoError(err)
	req.Equal(deposit, cachedDeposit)

	hash := crypto.Sha256Hash([]byte("missing-kernel-transaction")).String()
	ver, err := grp.ReadKernelTransactionUntilSufficient(ctx, hash)
	req.NoError(err)
	req.NotNil(ver)
	ver, err = grp.ReadKernelTransactionUntilSufficient(ctx, hash)
	req.NoError(err)
	req.NotNil(ver)
	badHash := crypto.Sha256Hash([]byte("invalid-cache")).String()
	req.NoError(grp.store.WriteCache(ctx, "readKernelTransactionUntilSufficient("+badHash+")", "not-base64"))
	req.Panics(func() { grp.ReadKernelTransactionUntilSufficient(ctx, badHash) })

	cachedRequest := &SafeTransactionRequest{RequestID: "cached", State: SafeUtxoStateSpent}
	b, err = json.Marshal(cachedRequest)
	req.NoError(err)
	req.NoError(grp.store.WriteCache(ctx, "readTransactionUntilSufficient(cached)", string(b)))
	request, err := grp.readTransactionUntilSufficient(ctx, "cached")
	req.NoError(err)
	req.Equal(cachedRequest.RequestID, request.RequestID)

	grp.writeDrainingCheckpoint(ctx, 123)
	checkpoint, err := grp.readDrainingCheckpoint(ctx)
	req.NoError(err)
	req.Equal(uint64(123), checkpoint)
	req.NoError(grp.store.WriteProperty(ctx, outputsDrainingKey, "invalid"))
	_, err = grp.readDrainingCheckpoint(ctx)
	req.Error(err)
	_, err = grp.readSafeOutputsAsUnspent(ctx, nil, 2, 0, 0)
	req.ErrorContains(err, "invalid members")

	filter := map[string]bool{}
	old := &UnifiedOutput{OutputId: uuid.Must(uuid.NewV4()).String(), Sequence: grp.epoch - 1}
	checkpoint = grp.processSafeOutputs(ctx, filter, 0, []*UnifiedOutput{old})
	req.Equal(old.Sequence, checkpoint)
	filtered := &UnifiedOutput{OutputId: uuid.Must(uuid.NewV4()).String(), Sequence: grp.epoch + 1}
	filter["ACT:"+filtered.OutputId+":"+decimal.NewFromInt(int64(filtered.Sequence)).String()] = true
	checkpoint = grp.processSafeOutputs(ctx, filter, checkpoint, []*UnifiedOutput{filtered})
	req.Equal(filtered.Sequence, checkpoint)

	output := &UnifiedOutput{OutputIndex: 0}
	app, err := grp.checkChange(ctx, output, common.NewTransactionV5(common.XINAssetId).AsVersioned())
	req.NoError(err)
	req.Empty(app)
}

func TestCoverageStoreWithdrawalLifecycle(t *testing.T) {
	req := require.New(t)
	ctx, node := testBuildGroup(req)
	grp := node.Group
	defer teardownTestDatabase(grp.store)

	assetID := uuid.Must(uuid.NewV4()).String()
	out := testBuildOutput(grp, req, assetID, "1", "", SafeUtxoStateUnspent, grp.epoch+10, "")
	req.NoError(grp.store.WriteAction(ctx, out, ActionStateInitial))
	actions, err := grp.store.ListActions(ctx, ActionStateInitial, 1)
	req.NoError(err)
	req.Len(actions, 1)
	action := actions[0]
	action.TestAttachActionToGroup(grp)
	req.False(action.Restored())

	ref := crypto.Sha256Hash([]byte("reference"))
	req.Panics(func() {
		action.BuildTransactionWithReference(ctx, uuid.Must(uuid.NewV4()).String(), grp.GroupId, assetID, "0.5", "", grp.GetMembers(), grp.GetThreshold(), crypto.Hash{})
	})
	normal := action.BuildTransactionWithReference(ctx, uuid.Must(uuid.NewV4()).String(), grp.GroupId, assetID, "0.5", "", grp.GetMembers(), grp.GetThreshold(), ref)
	req.Equal(ref, normal.references[0])
	action.consumed[assetID] = 0
	req.Panics(func() {
		action.BuildTransactionWithStorageTraceId(ctx, uuid.Must(uuid.NewV4()).String(), grp.GroupId, assetID, "0.5", "", grp.GetMembers(), grp.GetThreshold(), "invalid")
	})
	req.Panics(func() { action.BuildStorageTransaction(ctx, make([]byte, common.ExtraSizeStorageCapacity+1)) })

	traceID := uuid.Must(uuid.NewV4()).String()
	tx := action.BuildWithdrawTransaction(ctx, traceID, assetID, "0.5", "memo", "destination", "tag")
	req.True(tx.IsWithdrawal())
	req.NoError(grp.store.FinishAction(ctx, action.OutputId, ActionStateDone, []*Transaction{tx}))
	req.Empty(grp.ReadFinishedTxHashByTraceId(ctx, traceID))

	assigned := grp.ListOutputsForTransaction(ctx, traceID, tx.Sequence)
	req.Len(assigned, 1)
	ver, consumed, change, err := grp.buildRawTransaction(ctx, tx, assigned)
	req.NoError(err)
	req.Len(consumed, 1)
	req.True(change.Sign() > 0)
	raw := hex.EncodeToString(ver.Marshal())
	request, err := grp.createMultisigUntilSufficient(ctx, tx.RequestID(), raw)
	req.NoError(err)
	checked, err := CheckMultisigRequestRawTransaction(request, ver)
	req.NoError(err)
	req.Equal(ver.PayloadHash(), checked.PayloadHash())
	signed, err := grp.signMultisigUntilSufficient(ctx, request)
	req.NoError(err)
	req.NotEmpty(signed.Signers)
	_, err = grp.updateTxWithOutputs(ctx, tx, consumed, request, change)
	req.NoError(err)

	snapshot, err := grp.snapshotTransaction(ctx, tx)
	req.NoError(err)
	req.False(snapshot)
	req.NoError(grp.publishTransactions(ctx))
	req.NoError(grp.store.FinishTransaction(ctx, traceID))
	req.Equal(tx.Hash.String(), grp.ReadFinishedTxHashByTraceId(ctx, traceID))
	byHash, err := grp.store.ReadTransactionByHash(ctx, tx.Hash)
	req.NoError(err)
	req.Equal(traceID, byHash.TraceId)

	unconfirmed := grp.ListUnconfirmedWithdrawalTransactions(ctx, 10)
	req.Len(unconfirmed, 1)
	offset := time.Now().Add(-time.Hour)
	req.NoError(grp.store.ConfirmWithdrawalTransaction(ctx, traceID, "withdrawal-hash"))
	req.Empty(grp.ListUnconfirmedWithdrawalTransactions(ctx, 10))
	confirmed := grp.ListConfirmedWithdrawalTransactionsAfter(ctx, offset, 10)
	req.Len(confirmed, 1)
	req.Equal("withdrawal-hash", confirmed[0].WithdrawalHash.String)

	listed, err := grp.store.listOutputs(ctx, []string{out.OutputId})
	req.NoError(err)
	req.Len(listed, 1)
	_, err = grp.store.listOutputs(ctx, []string{"invalid"})
	req.Error(err)
	req.Panics(func() { grp.TestUpdateOutputsState(context.Background(), listed, string(SafeUtxoStateUnspent)) })
	req.NoError(grp.TestUpdateOutputsState(ctx, listed, string(SafeUtxoStateUnspent)))

	requestFromStore, err := grp.readTransactionUntilSufficientImpl(ctx, traceID)
	req.NoError(err)
	req.Equal(traceID, requestFromStore.RequestID)
	req.Equal(tx.Hash.String(), requestFromStore.TransactionHash)
}

func TestCoverageRowAndSQLiteErrorPaths(t *testing.T) {
	req := require.New(t)
	noRows := coverageRow{err: sql.ErrNoRows}
	failure := coverageRow{err: errors.New("scan")}

	action, err := actionFromRow(noRows)
	req.NoError(err)
	req.Nil(action)
	action, err = actionJoinFromRow(noRows)
	req.NoError(err)
	req.Nil(action)
	_, err = actionJoinFromRow(failure)
	req.Error(err)
	output, err := outputFromRow(noRows)
	req.NoError(err)
	req.Nil(output)
	_, err = outputFromRow(failure)
	req.Error(err)
	iteration, err := iterationFromRow(noRows)
	req.NoError(err)
	req.Nil(iteration)
	transaction, err := transactionFromRow(noRows)
	req.NoError(err)
	req.Nil(transaction)
	_, err = transactionFromRow(failure)
	req.Error(err)

	req.Panics(func() { closeOrPanic(coverageCloser{err: errors.New("close")}) })
	closeOrPanic(coverageCloser{})
	req.Equal(os.Getenv("HOME")+"/safe", ExpandTilde("~/safe"))
	req.Equal("/tmp/safe", ExpandTilde("/tmp/safe"))

	store, err := OpenSQLite3Store(t.TempDir() + "/mtg.sqlite3")
	req.NoError(err)
	req.Equal("INSERT INTO sample (a,b) VALUES (?, ?)", buildInsertionSQL("sample", []string{"a", "b"}))
	req.NoError(store.Close())
	_, err = store.ReadProperty(context.Background(), "closed")
	req.Error(err)
}

func first(a string, _ []byte) string {
	return a
}

func mustReadMTGCache(t *testing.T, store *SQLite3Store, ctx context.Context, key string) string {
	t.Helper()
	value, err := store.ReadCache(ctx, key)
	require.NoError(t, err)
	return value
}
