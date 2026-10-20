package signer

import (
	"bytes"
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost"
	"github.com/MixinNetwork/safe/apps/mixin"
	"github.com/MixinNetwork/safe/common"
	"github.com/stretchr/testify/require"
)

func TestConcurrentDerivedKeyCache(t *testing.T) {
	var public, encodedShare string
	for _, fixture := range testFROSTKeys {
		public, encodedShare, _ = strings.Cut(fixture, ";")
		break
	}
	share, err := hex.DecodeString(encodedShare)
	require.NoError(t, err)
	config := frost.EmptyConfig(curve.Edwards25519{})
	require.NoError(t, config.UnmarshalBinary(share))
	config.ChainKey = bytes.Repeat([]byte{1}, 32)
	share, err = config.MarshalBinary()
	require.NoError(t, err)
	node := &Node{derivedKeys: make(map[crypto.Hash][2][]byte)}
	const workers = 32
	expected := make([][]byte, workers)
	for i := range expected {
		expected[i] = mixin.DeriveEd25519Child(public, []byte{byte(i + 1), 0, 0, 0})
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Go(func() {
			<-start
			for step := range workers {
				i := (worker + step) % workers
				pub, _ := node.deriveByPath(t.Context(), common.CurveEdwards25519Default, share, []byte{byte(i + 1), 0, 0, 0})
				if !bytes.Equal(expected[i], pub) {
					t.Errorf("incorrect derived public key for path %d", i)
				}
			}
		})
	}
	close(start)
	wg.Wait()
}
