package observer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeriveBIP32WithKeeperPathRejectsMalformedPath(t *testing.T) {
	node := &Node{}
	for _, path := range []string{"", "04", "0100", "ff000000"} {
		_, err := node.deriveBIP32WithKeeperPath(t.Context(), "key", path)
		require.Error(t, err)
	}
}
