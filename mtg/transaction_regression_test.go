package mtg

import (
	"context"
	"crypto/rand"
	"slices"
	"sort"
	"testing"

	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/fox-one/mixin-sdk-go/v3/mixinnet"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestGhostKeysUseOutputIndexForEveryMember(t *testing.T) {
	addresses := make(map[string]*mixinnet.Address)
	var members []string
	for range 2 {
		addr := mixinnet.GenerateAddress(rand.Reader)
		addresses[addr.String()] = addr
		members = append(members, addr.String())
	}
	ma, err := mixin.NewMainnetMixAddress(members, 2)
	require.NoError(t, err)
	tx := &Transaction{
		TraceId: uuid.Must(uuid.NewV4()).String(), AssetId: uuid.Must(uuid.NewV4()).String(),
		OpponentAppId: uuid.Must(uuid.NewV4()).String(),
	}
	// Both outputs have the same members; only the output index changes.
	recipients := []*TransactionRecipient{{MixAddress: ma}, {MixAddress: ma}}
	gks, err := (&Group{}).createGhostKeysUntilSufficient(context.Background(), tx, recipients)
	require.NoError(t, err)
	for outputIndex := range recipients {
		for memberIndex, member := range ma.Members() {
			a := addresses[member]
			private := mixinnet.DeriveGhostPrivateKey(mixinnet.TxVersionHashSignature,
				&gks[outputIndex].Mask, &a.PrivateViewKey, &a.PrivateSpendKey, uint8(outputIndex))
			require.Equal(t, private.Public(), gks[outputIndex].Keys[memberIndex],
				"output %d, member %d", outputIndex, memberIndex)
		}
	}
}

func TestBuildTransactionOwnsSortedReceivers(t *testing.T) {
	req := require.New(t)
	ctx, node := testBuildGroup(req)
	t.Cleanup(func() { teardownTestDatabase(node.Group.store) })
	outputs := testDrainInitialOutputs(ctx, req, node.Group, 1, "")
	act := &Action{UnifiedOutput: *outputs[0]}
	act.TestAttachActionToGroup(node.Group)
	receivers := []string{mixinnet.GenerateAddress(rand.Reader).String(), mixinnet.GenerateAddress(rand.Reader).String()}
	sort.Sort(sort.Reverse(sort.StringSlice(receivers)))
	original := slices.Clone(receivers)
	expected := slices.Clone(receivers)
	sort.Strings(expected)
	tx := act.BuildTransaction(ctx, uuid.Must(uuid.NewV4()).String(), node.Group.GroupId,
		USDTAssetId, "0.0001", "", receivers, 1)
	require.Equal(t, expected, tx.Receivers)
	require.Equal(t, original, receivers, "building must preserve the caller's slice")
	receivers[0] = "reused by caller"
	require.Equal(t, expected, tx.Receivers, "the transaction must own its receiver slice")
}
