package signer

import (
	"testing"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/stretchr/testify/require"
)

func TestSignerResultsFindQuorumAfterMissingOrDifferentResult(t *testing.T) {
	conf := &Configuration{MTG: &mtg.Configuration{}}
	conf.MTG.Genesis.Members = []string{"a", "b", "c", "d"}
	node := &Node{conf: conf, threshold: 2}
	session := &Session{Operation: common.OperationTypeSignInput}
	for _, first := range []string{"", "02"} {
		results := map[string]string{"a": first, "b": "01", "c": "01", "d": "01"}
		ok, sig := node.verifySessionSignerResults(t.Context(), session, results)
		require.True(t, ok)
		require.Equal(t, []byte{1}, sig)
	}
	results := map[string]string{"a": "01", "b": "01", "c": "02", "d": "02", "outsider": "01"}
	ok, _ := node.verifySessionSignerResults(t.Context(), session, results)
	require.False(t, ok)
}
