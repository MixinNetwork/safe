package mtg

import (
	"testing"

	"github.com/MixinNetwork/mixin/common"
	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/stretchr/testify/require"
)

func TestMalformedMultisigResponseLeavesOutputsUnsigned(t *testing.T) {
	for _, raw := range []string{"zz", "00"} {
		output := &UnifiedOutput{State: SafeUtxoStateUnspent}
		_, err := (&Group{}).updateTxWithOutputs(t.Context(), &Transaction{TraceId: "trace"}, []*UnifiedOutput{output},
			&mixin.SafeMultisigRequest{RawTransaction: raw, TransactionHash: "hash"}, common.NewInteger(0))
		require.Error(t, err)
		require.Equal(t, SafeUtxoStateUnspent, output.State)
		require.Empty(t, output.TraceId)
		require.Empty(t, output.SignedBy)
	}
}

func TestStorageAcceptsExactRequiredBalance(t *testing.T) {
	req := require.New(t)
	ctx, node := testBuildGroup(req)
	group := node.Group
	defer teardownTestDatabase(group.store)
	extra := []byte("storage")
	amount := getStorageTransactionAmount(extra).String()
	output := testBuildOutput(group, req, StorageAssetId, amount, "", SafeUtxoStateUnspent, group.epoch+1, "")
	req.NoError(group.store.WriteAction(ctx, output, ActionStateInitial))
	actions, err := group.store.ListActions(ctx, ActionStateInitial, 1)
	req.NoError(err)
	req.Len(actions, 1)
	action := actions[0]
	action.TestAttachActionToGroup(group)
	req.True(action.CheckAssetBalanceForStorageAt(ctx, extra))
	tx := action.BuildStorageTransaction(ctx, extra)
	req.Equal(amount, tx.Amount)
	req.Len(tx.consumed, 1)
	req.False(action.CheckAssetBalanceForStorageAt(ctx, extra))
}
