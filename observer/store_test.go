package observer

import (
	"fmt"
	"testing"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/stretchr/testify/require"
)

func TestRecoveryCreationAndApprovalAreAtomic(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing approval %t", existing), func(t *testing.T) {
			s := coverageObserverStore(t)
			ctx := t.Context()
			now := time.Now().UTC()
			approval := coverageObserverTransaction("atomic-recovery", common.RequestStateInitial, common.SafeChainBitcoin, now)
			recovery := &Recovery{
				Address: "address", Chain: approval.Chain, Holder: approval.Holder, Observer: "observer", RawTransaction: "recovery-raw",
				TransactionHash: approval.TransactionHash, State: common.RequestStateInitial, CreatedAt: now, UpdatedAt: now,
			}
			if existing {
				require.NoError(t, s.WriteTransactionApprovalIfNotExists(ctx, approval))
			}
			_, err := s.db.ExecContext(ctx, `CREATE TRIGGER fail_recovery BEFORE INSERT ON recoveries BEGIN SELECT RAISE(ABORT, 'recovery insert failed'); END`)
			require.NoError(t, err)
			require.ErrorContains(t, s.WriteInitialRecoveryWithApproval(ctx, recovery, approval), "recovery insert failed")
			stored, err := s.ReadTransactionApproval(ctx, approval.TransactionHash)
			require.NoError(t, err)
			if existing {
				require.NotNil(t, stored)
				require.Equal(t, approval.RawTransaction, stored.RawTransaction)
			} else {
				require.Nil(t, stored, "failed recovery must not leave an approval that blocks retries")
			}
			storedRecovery, err := s.ReadRecoveryByHash(ctx, recovery.TransactionHash)
			require.NoError(t, err)
			require.Nil(t, storedRecovery)
			_, err = s.db.ExecContext(ctx, "DROP TRIGGER fail_recovery")
			require.NoError(t, err)
			require.NoError(t, s.WriteInitialRecoveryWithApproval(ctx, recovery, approval))
			stored, err = s.ReadTransactionApproval(ctx, approval.TransactionHash)
			require.NoError(t, err)
			require.NotNil(t, stored)
			storedRecovery, err = s.ReadRecoveryByHash(ctx, recovery.TransactionHash)
			require.NoError(t, err)
			require.NotNil(t, storedRecovery)
			require.Equal(t, recovery.RawTransaction, storedRecovery.RawTransaction)
		})
	}
}

func TestReadObserverKeyRejectsMalformedChainCode(t *testing.T) {
	s := coverageObserverStore(t)
	require.NoError(t, s.WriteObserverKeys(t.Context(), common.CurveSecp256k1ECDSABitcoin, map[string]string{"public": "invalid hex"}))
	_, _, err := s.ReadObserverKey(t.Context(), common.CurveSecp256k1ECDSABitcoin)
	require.Error(t, err)
}
