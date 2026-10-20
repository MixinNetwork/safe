package keeper

import (
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

func TestInheritanceRemovalRejectsAnotherSafe(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "safe.sqlite3")
	s, err := OpenSQLite3Store(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	db, err := common.OpenSQLite3Store(path, "")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	now := time.Now().UTC()
	lockID := uuid.Must(uuid.NewV4())
	_, err = db.ExecContext(ctx, `INSERT INTO inheritance_locks
		(lock_id,request_id,hash,holder,address,chain,duration,state,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`, lockID.String(), uuid.Must(uuid.NewV4()).String(), "commitment", "victim", "victim-address", common.SafeChainBitcoin, int64(400*24*time.Hour), common.RequestStateDone, now, now)
	require.NoError(t, err)
	safe := &store.Safe{Holder: "attacker", Address: "attacker-address", Chain: common.SafeChainBitcoin,
		Signer: "signer", Observer: "observer", Receivers: []string{"receiver"}, Threshold: 1,
		State: common.RequestStatePending, Extra: []byte{}, CreatedAt: now, UpdatedAt: now}
	require.NoError(t, s.WriteUnfinishedSafe(ctx, safe))
	id := uuid.Must(uuid.NewV4()).String()
	extra := append(lockID.Bytes(), uuid.Must(uuid.NewV4()).Bytes()...)
	req := &common.Request{Id: id, MixinHash: crypto.Sha256Hash([]byte(id)), AssetId: uuid.Must(uuid.NewV4()).String(),
		Amount: decimal.NewFromInt(1), Role: common.RequestRoleHolder, Action: common.ActionBitcoinSafeProposeTransaction,
		Curve: common.CurveSecp256k1ECDSABitcoin, Holder: safe.Holder, State: common.RequestStateInitial,
		CreatedAt: now, ExtraHEX: hex.EncodeToString(append([]byte{common.FlagProposeRemoveInheritance}, extra...)),
		Output: &mtg.Action{UnifiedOutput: mtg.UnifiedOutput{OutputId: uuid.Must(uuid.NewV4()).String()}}}
	require.NoError(t, s.WriteRequestIfNotExist(ctx, req))
	node := &Node{store: s}
	_, _, err = node.processSafeInheritanceLock(ctx, req, safe, common.FlagProposeRemoveInheritance, extra)
	require.ErrorContains(t, err, "invalid lock to remove")
	tx := &store.Transaction{TransactionHash: crypto.Sha256Hash([]byte("tx")).String(), RawTransaction: "00",
		Holder: safe.Holder, Chain: safe.Chain, AssetId: req.AssetId, State: common.RequestStateInitial,
		RequestId: req.Id, CreatedAt: now, UpdatedAt: now}
	require.NoError(t, s.WriteTransactionWithRequest(ctx, tx, nil, nil, nil, req))
	foreign, err := s.ReadInheritanceLock(ctx, lockID.String())
	require.NoError(t, err)
	foreign.State = common.RequestStateFailed
	require.ErrorContains(t, s.FinishTransactionSignaturesWithRequest(ctx, tx, "00", req, 0, safe, nil, foreign, nil), "does not belong")
	lock := node.finalizePendingSafeInheritanceLock(ctx, tx)
	require.Nil(t, lock, "previously accepted foreign removals must also be ignored at finalization")
	require.NoError(t, s.FinishTransactionSignaturesWithRequest(ctx, tx, "00", req, 0, safe, nil, lock, nil))
	victim, err := s.ReadInheritanceLock(ctx, lockID.String())
	require.NoError(t, err)
	require.Equal(t, byte(common.RequestStateDone), victim.State, "another safe's transaction must preserve the victim's lock")
}

func TestInheritanceRemovalAcceptsOwnerAndRejectsOtherChains(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "safe.sqlite3")
	s, err := OpenSQLite3Store(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	db, err := common.OpenSQLite3Store(path, "")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	now := time.Now().UTC()
	lockID := uuid.Must(uuid.NewV4())
	_, err = db.ExecContext(ctx, `INSERT INTO inheritance_locks
        (lock_id,request_id,hash,holder,address,chain,duration,state,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)`, lockID.String(), uuid.Must(uuid.NewV4()).String(), "commitment", "holder", "address",
		common.SafeChainBitcoin, int64(400*24*time.Hour), common.RequestStateDone, now, now)
	require.NoError(t, err)
	extra := append(lockID.Bytes(), uuid.Must(uuid.NewV4()).Bytes()...)
	node := &Node{store: s}
	safe := &store.Safe{Holder: "holder", Address: "address", Chain: common.SafeChainBitcoin}
	_, suffix, err := node.processSafeInheritanceLock(ctx, &common.Request{}, safe, common.FlagProposeRemoveInheritance, extra)
	require.NoError(t, err)
	require.Equal(t, extra[16:], suffix)
	safe.Chain = common.SafeChainLitecoin
	_, _, err = node.processSafeInheritanceLock(ctx, &common.Request{}, safe, common.FlagProposeRemoveInheritance, extra)
	require.Error(t, err)
	safe.Chain = common.SafeChainBitcoin
	safe.Address = "different-address"
	_, _, err = node.processSafeInheritanceLock(ctx, &common.Request{}, safe, common.FlagProposeRemoveInheritance, extra)
	require.Error(t, err)
}
