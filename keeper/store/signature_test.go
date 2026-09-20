package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/stretchr/testify/require"
)

func TestCountCollectedUniqueSignatures(t *testing.T) {
	const hash = "transaction-hash"
	signed := sql.NullString{String: "abcd", Valid: true}
	unsigned := sql.NullString{}
	type signatureRow struct {
		hash      string
		input     int
		state     int
		signature sql.NullString
	}

	for _, test := range []struct {
		name string
		rows []signatureRow
		want int
	}{
		{name: "no requests"},
		{
			name: "unsigned requests in every state",
			rows: []signatureRow{
				{hash, 0, common.RequestStateInitial, unsigned},
				{hash, 1, common.RequestStatePending, unsigned},
				{hash, 2, common.RequestStateDone, unsigned},
				{hash, 3, common.RequestStateFailed, unsigned},
			},
		},
		{
			name: "pending signature is already collected",
			rows: []signatureRow{{hash, 0, common.RequestStatePending, signed}},
			want: 1,
		},
		{
			name: "completed signature",
			rows: []signatureRow{{hash, 0, common.RequestStateDone, signed}},
			want: 1,
		},
		{
			name: "collected signature survives failed request",
			rows: []signatureRow{{hash, 0, common.RequestStateFailed, signed}},
			want: 1,
		},
		{
			name: "retries for one input count once",
			rows: []signatureRow{
				{hash, 0, common.RequestStatePending, signed},
				{hash, 0, common.RequestStateDone, signed},
				{hash, 0, common.RequestStateInitial, unsigned},
			},
			want: 1,
		},
		{
			name: "distinct inputs with identical signatures",
			rows: []signatureRow{
				{hash, 0, common.RequestStatePending, signed},
				{hash, 7, common.RequestStateDone, signed},
				{hash, 8, common.RequestStateInitial, unsigned},
			},
			want: 2,
		},
		{
			name: "other transactions are excluded",
			rows: []signatureRow{
				{hash, 0, common.RequestStatePending, signed},
				{"other-transaction", 0, common.RequestStateDone, signed},
				{"other-transaction", 1, common.RequestStateDone, signed},
			},
			want: 1,
		},
		{
			name: "unknown transaction with signatures elsewhere",
			rows: []signatureRow{{"other-transaction", 0, common.RequestStateDone, signed}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, path := coverageStore(t)
			now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
			for i, row := range test.rows {
				_, err := s.db.ExecContext(t.Context(), `INSERT INTO signature_requests
					(request_id, transaction_hash, input_index, signer, curve, message, signature, state, created_at, updated_at)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					fmt.Sprintf("request-%d", i), row.hash, row.input, "signer", common.CurveSecp256k1ECDSABitcoin,
					"message", row.signature, row.state, now, now)
				require.NoError(t, err)
			}

			// The observer reads the keeper database through a read-only store.
			reader, err := OpenSQLite3ReadOnlyStore(path)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, reader.Close()) })
			count, err := reader.CountCollectedUniqueSignatures(t.Context(), hash)
			require.NoError(t, err)
			require.Equal(t, test.want, count)
		})
	}
}

func TestCountCollectedUniqueSignaturesErrors(t *testing.T) {
	t.Run("canceled context", func(t *testing.T) {
		s, _ := coverageStore(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := s.CountCollectedUniqueSignatures(ctx, "transaction-hash")
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("closed database", func(t *testing.T) {
		s, _ := coverageStore(t)
		require.NoError(t, s.Close())
		_, err := s.CountCollectedUniqueSignatures(t.Context(), "transaction-hash")
		require.ErrorContains(t, err, "database is closed")
	})
}

func TestWriteSignatureRequestsRollsBackOnDuplicate(t *testing.T) {
	s, _ := coverageStore(t)
	ctx := t.Context()
	proposal := coverageRequest(common.ActionEthereumSafeProposeTransaction)
	require.NoError(t, s.WriteRequestIfNotExist(ctx, proposal))
	transaction := coverageTransaction(proposal, proposal.Holder, common.SafeChainEthereum)
	require.NoError(t, s.WriteTransactionWithRequest(ctx, transaction, nil, nil, nil, proposal))
	approval := coverageRequest(common.ActionEthereumSafeApproveTransaction)
	approval.Holder = proposal.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, approval))

	signature := &SignatureRequest{
		RequestId: "duplicate-signature-request", TransactionHash: transaction.TransactionHash,
		Signer: "signer", Curve: common.CurveSecp256k1ECDSAEthereum, Message: "message",
		State: common.RequestStateInitial, CreatedAt: approval.CreatedAt, UpdatedAt: approval.CreatedAt,
	}
	err := s.WriteSignatureRequestsWithRequest(ctx, []*SignatureRequest{signature, signature}, transaction.TransactionHash, "updated-raw", approval, nil)
	require.ErrorContains(t, err, "INSERT signature_requests")

	storedTransaction, err := s.ReadTransaction(ctx, transaction.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, common.RequestStateInitial, storedTransaction.State)
	require.Equal(t, transaction.RawTransaction, storedTransaction.RawTransaction)
	storedApproval, err := s.ReadRequest(ctx, approval.Id)
	require.NoError(t, err)
	require.Equal(t, uint8(common.RequestStateInitial), storedApproval.State)
	storedSignature, err := s.ReadSignatureRequest(ctx, signature.RequestId)
	require.NoError(t, err)
	require.Nil(t, storedSignature)
	result, handled, err := s.ReadActionResult(ctx, approval.Output.OutputId, approval.Id)
	require.NoError(t, err)
	require.False(t, handled)
	require.Nil(t, result)
}
