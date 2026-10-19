package store

import (
	"testing"

	"github.com/MixinNetwork/safe/common"
	"github.com/stretchr/testify/require"
)

func TestEthereumSafeProposalIsAtomic(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		name := "success"
		if duplicate {
			name = "transaction conflict rolls back proposal"
		}
		t.Run(name, func(t *testing.T) {
			s, _ := coverageStore(t)
			ctx := t.Context()
			req := coverageRequest(common.ActionEthereumSafeProposeAccount)
			require.NoError(t, s.WriteRequestIfNotExist(ctx, req))
			transaction := coverageTransaction(req, req.Holder, common.SafeChainEthereum)
			if duplicate {
				previous := coverageRequest(common.ActionEthereumSafeProposeTransaction)
				require.NoError(t, s.WriteRequestIfNotExist(ctx, previous))
				existing := *transaction
				existing.RequestId = previous.Id
				require.NoError(t, s.WriteTransactionWithRequest(ctx, &existing, nil, nil, nil, previous))
			}
			proposal := &SafeProposal{
				RequestId: req.Id, Holder: req.Holder, Chain: common.SafeChainEthereum,
				Address: "safe-address", Signer: "signer", Observer: "observer", Extra: []byte("deployment"),
				Receivers: []string{"receiver"}, Threshold: 1, CreatedAt: req.CreatedAt, UpdatedAt: req.CreatedAt,
			}
			err := s.WriteEthereumSafeProposalWithRequest(ctx, proposal, transaction, nil, req)
			if duplicate {
				require.ErrorContains(t, err, "INSERT transactions")
			} else {
				require.NoError(t, err)
			}
			storedProposal, err := s.ReadSafeProposal(ctx, req.Id)
			require.NoError(t, err)
			storedRequest, err := s.ReadRequest(ctx, req.Id)
			require.NoError(t, err)
			result, handled, err := s.ReadActionResult(ctx, req.Output.OutputId, req.Id)
			require.NoError(t, err)
			if duplicate {
				require.Nil(t, storedProposal)
				require.Equal(t, uint8(common.RequestStateInitial), storedRequest.State)
				require.False(t, handled)
				require.Nil(t, result)
				return
			}
			require.Equal(t, proposal, storedProposal)
			storedTransaction, err := s.ReadTransaction(ctx, transaction.TransactionHash)
			require.NoError(t, err)
			require.Equal(t, transaction, storedTransaction)
			require.Equal(t, uint8(common.RequestStateDone), storedRequest.State)
			require.True(t, handled)
			require.Equal(t, req.Id, result.RequestId)
		})
	}
}

func TestCloseAccountByTransactionIsAtomicAndReplayable(t *testing.T) {
	s, _ := coverageStore(t)
	ctx := t.Context()
	creation := coverageRequest(common.ActionEthereumSafeApproveAccount)
	safe := coverageSafe(creation.Holder, "safe-address", common.SafeChainEthereum, common.RequestStateDone)
	safe.RequestId = creation.Id
	require.NoError(t, s.WriteRequestIfNotExist(ctx, creation))
	require.NoError(t, s.WriteSafeWithRequest(ctx, safe, nil, creation))
	req := coverageRequest(common.ActionEthereumSafeCloseAccount)
	req.Holder = safe.Holder
	transaction := coverageTransaction(req, safe.Holder, safe.Chain)

	// Failure after the safe update must roll back both closure and insertion.
	err := s.CloseAccountByTransactionWithRequest(ctx, transaction, nil, common.RequestStateDone, nil, req)
	require.ErrorContains(t, err, "UPDATE requests")
	storedSafe, err := s.ReadSafe(ctx, safe.Holder)
	require.NoError(t, err)
	require.Equal(t, byte(common.RequestStateDone), storedSafe.State)
	storedTransaction, err := s.ReadTransaction(ctx, transaction.TransactionHash)
	require.NoError(t, err)
	require.Nil(t, storedTransaction)

	require.NoError(t, s.WriteRequestIfNotExist(ctx, req))
	for range 2 {
		require.NoError(t, s.CloseAccountByTransactionWithRequest(ctx, transaction, nil, common.RequestStateDone, nil, req))
		storedSafe, err = s.ReadSafe(ctx, safe.Holder)
		require.NoError(t, err)
		require.Equal(t, byte(common.RequestStateFailed), storedSafe.State)
		storedTransaction, err = s.ReadTransaction(ctx, transaction.TransactionHash)
		require.NoError(t, err)
		require.Equal(t, transaction, storedTransaction)
		storedRequest, err := s.ReadRequest(ctx, req.Id)
		require.NoError(t, err)
		require.Equal(t, uint8(common.RequestStateDone), storedRequest.State)
		result, handled, err := s.ReadActionResult(ctx, req.Output.OutputId, req.Id)
		require.NoError(t, err)
		require.True(t, handled)
		require.Equal(t, req.Id, result.RequestId)
	}
}

func TestCloseAccountBySignatureRequestsIsAtomic(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		name := "success"
		if duplicate {
			name = "duplicate signature rolls back closure"
		}
		t.Run(name, func(t *testing.T) {
			s, _ := coverageStore(t)
			ctx := t.Context()
			creation := coverageRequest(common.ActionEthereumSafeApproveAccount)
			safe := coverageSafe(creation.Holder, "safe-address", common.SafeChainEthereum, common.RequestStateDone)
			safe.RequestId = creation.Id
			require.NoError(t, s.WriteRequestIfNotExist(ctx, creation))
			require.NoError(t, s.WriteSafeWithRequest(ctx, safe, nil, creation))
			proposal := coverageRequest(common.ActionEthereumSafeProposeTransaction)
			proposal.Holder = safe.Holder
			require.NoError(t, s.WriteRequestIfNotExist(ctx, proposal))
			transaction := coverageTransaction(proposal, safe.Holder, safe.Chain)
			require.NoError(t, s.WriteTransactionWithRequest(ctx, transaction, nil, nil, nil, proposal))
			req := coverageRequest(common.ActionEthereumSafeCloseAccount)
			req.Holder = safe.Holder
			require.NoError(t, s.WriteRequestIfNotExist(ctx, req))
			signature := &SignatureRequest{
				RequestId: "signature-request", TransactionHash: transaction.TransactionHash,
				Signer: safe.Signer, Curve: common.CurveSecp256k1ECDSAEthereum, Message: "message",
				State: common.RequestStateInitial, CreatedAt: req.CreatedAt, UpdatedAt: req.CreatedAt,
			}
			signatures := []*SignatureRequest{signature}
			if duplicate {
				signatures = append(signatures, signature)
			}
			err := s.CloseAccountBySignatureRequestsWithRequest(ctx, signatures, transaction.TransactionHash, "signed-raw", req, nil)
			if duplicate {
				require.ErrorContains(t, err, "INSERT signature_requests")
			} else {
				require.NoError(t, err)
			}
			storedSafe, err := s.ReadSafe(ctx, safe.Holder)
			require.NoError(t, err)
			storedTransaction, err := s.ReadTransaction(ctx, transaction.TransactionHash)
			require.NoError(t, err)
			storedRequest, err := s.ReadRequest(ctx, req.Id)
			require.NoError(t, err)
			storedSignature, err := s.ReadSignatureRequest(ctx, signature.RequestId)
			require.NoError(t, err)
			result, handled, err := s.ReadActionResult(ctx, req.Output.OutputId, req.Id)
			require.NoError(t, err)
			if duplicate {
				require.Equal(t, byte(common.RequestStateDone), storedSafe.State)
				require.Equal(t, transaction, storedTransaction)
				require.Equal(t, uint8(common.RequestStateInitial), storedRequest.State)
				require.Nil(t, storedSignature)
				require.False(t, handled)
				require.Nil(t, result)
				return
			}
			require.Equal(t, byte(common.RequestStateFailed), storedSafe.State)
			require.Equal(t, common.RequestStatePending, storedTransaction.State)
			require.Equal(t, "signed-raw", storedTransaction.RawTransaction)
			require.Equal(t, uint8(common.RequestStateDone), storedRequest.State)
			require.Equal(t, signature, storedSignature)
			require.True(t, handled)
			require.Equal(t, req.Id, result.RequestId)
		})
	}
}
