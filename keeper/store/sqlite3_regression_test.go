package store

import (
	"context"
	"testing"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/stretchr/testify/require"
)

func TestReadsUseTheirTransactionConnection(t *testing.T) {
	s, _ := coverageStore(t)
	req := coverageRequest(common.ActionBitcoinSafeApproveAccount)
	safe := coverageSafe(req.Holder, "safe-address", common.SafeChainBitcoin, common.RequestStateDone)
	safe.RequestId = req.Id
	require.NoError(t, s.WriteRequestIfNotExist(t.Context(), req))
	require.NoError(t, s.WriteSafeWithRequest(t.Context(), safe, nil, req))
	s.db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err := s.ListAllBitcoinUTXOsForHolder(ctx, safe.Holder)
	require.NoError(t, err)
	_, err = s.ListPendingBitcoinUTXOsForHolder(ctx, safe.Holder)
	require.NoError(t, err)
	_, err = s.ReadUnspentUtxoCountForSafe(ctx, safe.Address)
	require.NoError(t, err)
	_, err = s.ReadAllEthereumTokenBalances(ctx, safe.Address)
	require.NoError(t, err)
	_, err = s.ListInheritanceLocksByHolder(ctx, safe.Holder)
	require.NoError(t, err)
	_, err = s.ListAllBitcoinUTXOsForHolder(ctx, "missing")
	require.NoError(t, err)
	_, err = s.ListPendingBitcoinUTXOsForHolder(ctx, "missing")
	require.NoError(t, err)
}

func TestExistenceReturnsIterationError(t *testing.T) {
	s, _ := coverageStore(t)
	tx, err := s.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer common.Rollback(tx)
	exists, err := s.checkExistence(t.Context(), tx, "SELECT abs(-9223372036854775808)")
	require.ErrorContains(t, err, "integer overflow")
	require.False(t, exists)
}

func TestEmptySignatureRequestsPreserveAtomicity(t *testing.T) {
	for _, failAction := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[failAction], func(t *testing.T) {
			s, _ := coverageStore(t)
			req := coverageRequest(common.ActionBitcoinSafeApproveTransaction)
			require.NoError(t, s.WriteRequestIfNotExist(t.Context(), req))
			if failAction {
				_, err := s.db.Exec("DROP TABLE action_results")
				require.NoError(t, err)
			}
			err := s.WriteSignatureRequestsWithRequest(t.Context(), nil, "", "", req, nil)
			stored, readErr := s.ReadRequest(t.Context(), req.Id)
			require.NoError(t, readErr)
			if failAction {
				require.Error(t, err)
				require.Equal(t, byte(common.RequestStateInitial), stored.State)
				return
			}
			require.NoError(t, err)
			require.Equal(t, byte(common.RequestStateDone), stored.State)
			result, handled, err := s.ReadActionResult(t.Context(), req.Output.OutputId, req.Id)
			require.NoError(t, err)
			require.True(t, handled)
			require.NotNil(t, result)
		})
	}
}
