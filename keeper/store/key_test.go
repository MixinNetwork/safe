package store

import (
	"testing"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/stretchr/testify/require"
)

func TestAssignKeysUsesRequestTimeForMaturity(t *testing.T) {
	ctx := t.Context()
	s, _ := coverageStore(t)
	createdAt := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	var publics []string
	for _, role := range []byte{common.RequestRoleSigner, common.RequestRoleObserver} {
		req := coverageKeyRequest(role, createdAt)
		require.NoError(t, s.WriteRequestIfNotExist(ctx, req))
		require.NoError(t, s.WriteKeyFromRequest(ctx, req, int(role), nil, common.RequestFlagNone))
		publics = append(publics, req.Holder)
	}

	const maturity = 24 * time.Hour
	req := coverageRequest(common.ActionBitcoinSafeProposeAccount)
	for _, age := range []time.Duration{maturity / 2, maturity} {
		req.CreatedAt = createdAt.Add(age)
		signer, observer, err := s.AssignSignerAndObserverToHolder(ctx, req, maturity, "")
		require.NoError(t, err)
		require.Empty(t, signer)
		require.Empty(t, observer)
	}

	req.CreatedAt = createdAt.Add(maturity + time.Nanosecond)
	signer, observer, err := s.AssignSignerAndObserverToHolder(ctx, req, maturity, "")
	require.NoError(t, err)
	require.Equal(t, publics[0], signer)
	require.Equal(t, publics[1], observer)
}
