package keeper

import (
	"context"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/stretchr/testify/require"
)

// Advance the action timestamp instead of sleeping. Ethereum's observer gates
// retries by time; Bitcoin also enforces the timeout per input in the keeper.
func testSignatureTimeoutRetries(ctx context.Context, require *require.Assertions, node *Node, approval *mtg.Action, hash string) map[int]*store.SignatureRequest {
	req, err := node.parseRequest(approval)
	require.NoError(err)
	tx, err := node.store.ReadTransaction(ctx, hash)
	require.NoError(err)
	safe, err := node.store.ReadSafe(ctx, tx.Holder)
	require.NoError(err)
	unsigned, err := node.store.ListAllSignaturesForTransaction(ctx, hash, common.RequestStateInitial)
	require.NoError(err)
	require.NotEmpty(unsigned)
	collected, err := node.store.ListAllSignaturesForTransaction(ctx, hash, common.RequestStatePending)
	require.NoError(err)

	bitcoin := common.NormalizeCurve(req.Curve) == common.CurveSecp256k1ECDSABitcoin
	if bitcoin {
		earlyID := common.UniqueId(req.Id, "before signing timeout")
		early := testBuildObserverRequest(ctx, node, earlyID, req.Holder, req.Action, req.ExtraBytes(), req.Curve)
		early.SequencerCreatedAt = approval.SequencerCreatedAt.Add(SafeSignatureTimeout - time.Nanosecond)
		testStep(ctx, require, node, early)
		failed, err := node.store.ReadRequest(ctx, earlyID)
		require.NoError(err)
		require.Equal(uint8(common.RequestStateFailed), failed.State)
		for index, original := range unsigned {
			pending, err := node.store.ReadPendingSignatureRequestByTransactionIndex(ctx, hash, index)
			require.NoError(err)
			require.Equal(original.RequestId, pending.RequestId)
		}
	}

	// Repeated outages must produce distinct sessions, bound to the same
	// transaction and messages, while retaining any signatures already collected.
	previousID := req.Id
	for attempt := 1; attempt <= 2; attempt++ {
		retryID := common.UniqueId(previousID, "signing timeout")
		retry := testBuildObserverRequest(ctx, node, retryID, req.Holder, req.Action, req.ExtraBytes(), req.Curve)
		retry.SequencerCreatedAt = approval.SequencerCreatedAt.Add(time.Duration(attempt) * SafeSignatureTimeout)
		testStep(ctx, require, node, retry)
		accepted, err := node.store.ReadRequest(ctx, retryID)
		require.NoError(err)
		require.Equal(uint8(common.RequestStateDone), accepted.State)
		result, handled, err := node.store.ReadActionResult(ctx, retry.OutputId, retryID)
		require.NoError(err)
		require.True(handled)
		require.NotNil(result)
		require.Len(result.Transactions, len(unsigned), "only unsigned inputs need a new signing session")
		for index, original := range unsigned {
			pending, err := node.store.ReadPendingSignatureRequestByTransactionIndex(ctx, hash, index)
			require.NoError(err)
			require.NotNil(pending)
			require.Equal(common.UniqueId(retryID, original.Message), pending.RequestId)
			require.NotEqual(original.RequestId, pending.RequestId)
			require.Equal(hash, pending.TransactionHash)
			require.Equal(original.Message, pending.Message)
			require.Equal(common.RequestStateInitial, pending.State)
			unsigned[index] = pending
		}
		remaining, err := node.store.ListAllSignaturesForTransaction(ctx, hash, common.RequestStatePending)
		require.NoError(err)
		require.Equal(collected, remaining)
		unchanged, err := node.store.ReadTransaction(ctx, hash)
		require.NoError(err)
		unchanged.UpdatedAt = tx.UpdatedAt
		require.Equal(tx, unchanged, "retry must preserve transaction identity, contents and state")
		currentSafe, err := node.store.ReadSafe(ctx, tx.Holder)
		require.NoError(err)
		require.Equal(safe.State, currentSafe.State)
		require.Equal(safe.Nonce, currentSafe.Nonce, "retry must not consume a nonce")
		previousID = retryID
	}
	return unsigned
}
