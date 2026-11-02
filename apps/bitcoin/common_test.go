package bitcoin

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRecoveryTimelockRejectsUnconfirmedAndFutureOutputs(t *testing.T) {
	for _, chain := range []byte{ChainBitcoin, ChainLitecoin} {
		const height = uint64(1_000_000)
		lock := 24 * time.Hour
		blocks := uint64(lock / BlocksDuration(chain, 1))
		for _, outputHeight := range []uint64{0, math.MaxUint64, height + 1, height, height - 100, height - 100 - blocks} {
			require.False(t, CheckTimelock(chain, height, outputHeight, lock), "height %d", outputHeight)
		}
		require.True(t, CheckTimelock(chain, height, height-101-blocks, lock))
	}
}
