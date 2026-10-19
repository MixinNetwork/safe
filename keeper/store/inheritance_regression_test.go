package store

import (
	"testing"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestRevokedReplacementPreservesActiveInheritance(t *testing.T) {
	s, _ := coverageStore(t)
	ctx := t.Context()
	safe := coverageSafe("holder", "address", common.SafeChainEthereum, common.RequestStatePending)
	require.NoError(t, s.WriteUnfinishedSafe(ctx, safe))
	now := time.Now().UTC()
	oldID := uuid.Must(uuid.NewV4()).String()
	_, err := s.db.ExecContext(ctx, `INSERT INTO inheritance_locks
		(lock_id,request_id,hash,holder,address,chain,duration,state,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`, oldID, uuid.Must(uuid.NewV4()).String(), "commitment", safe.Holder, safe.Address,
		safe.Chain, int64(400*24*time.Hour), common.RequestStateDone, now.Add(-time.Hour), now.Add(-time.Hour))
	require.NoError(t, err)
	proposal := coverageRequest(common.ActionEthereumSafeProposeTransaction)
	proposal.Holder = safe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, proposal))
	tx := coverageTransaction(proposal, safe.Holder, safe.Chain)
	replacement := &InheritanceLock{LockId: uuid.Must(uuid.NewV4()).String(), RequestId: proposal.Id,
		Holder: safe.Holder, Address: safe.Address, Chain: safe.Chain, Duration: 500 * 24 * time.Hour,
		State: common.RequestStateInitial, CreatedAt: now, UpdatedAt: now}
	require.NoError(t, s.WriteTransactionWithRequest(ctx, tx, nil, replacement, nil, proposal))
	pendingActive, err := s.ReadActiveInheritanceLockByHolder(ctx, safe.Holder)
	require.NoError(t, err)
	require.NotNil(t, pendingActive)
	require.Equal(t, oldID, pendingActive.LockId, "an unapproved replacement must not disable the current lock")
	revoke := coverageRequest(common.ActionEthereumSafeRevokeTransaction)
	revoke.Holder = safe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, revoke))
	require.NoError(t, s.RevokeTransactionWithRequest(ctx, tx, safe, revoke, replacement, nil))
	active, err := s.ReadInheritanceLock(ctx, oldID)
	require.NoError(t, err)
	require.Equal(t, byte(common.RequestStateDone), active.State)
	// Recovery must still select the approved lock after the replacement is revoked.
	recoveryLock, err := s.ReadActiveInheritanceLockByHolder(ctx, safe.Holder)
	require.NoError(t, err)
	require.NotNil(t, recoveryLock)
	require.Equal(t, oldID, recoveryLock.LockId)
	_, err = s.db.ExecContext(ctx, "UPDATE inheritance_locks SET state=? WHERE lock_id=?", common.RequestStateFailed, oldID)
	require.NoError(t, err)
	recoveryLock, err = s.ReadActiveInheritanceLockByHolder(ctx, safe.Holder)
	require.NoError(t, err)
	require.Nil(t, recoveryLock, "removing the active lock must not revive an older failed lock")
}
