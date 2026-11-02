package mtg

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGroupRequiresExactDistinctMembers(t *testing.T) {
	const member = "0ca34767-3a70-4a28-afd9-51c9bce4ecf5"
	for _, app := range []string{"", member[:10]} {
		conf := &Configuration{}
		conf.App.AppId = app
		conf.Genesis.Members = []string{member}
		conf.Genesis.Threshold = 1
		_, err := BuildGroup(t.Context(), nil, conf)
		require.ErrorContains(t, err, "does not belong")
	}
	conf := &Configuration{}
	conf.App.AppId = member
	conf.Genesis.Members = []string{member, member}
	conf.Genesis.Threshold = 2
	_, err := BuildGroup(t.Context(), nil, conf)
	require.ErrorContains(t, err, "duplicate group member")
}
