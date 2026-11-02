package observer

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	keeperstore "github.com/MixinNetwork/safe/keeper/store"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestBitcoinRecoveryMalformedHexReturnsError(t *testing.T) {
	node := &Node{store: coverageObserverStore(t)}
	safe := &keeperstore.Safe{Holder: "holder"}
	for _, raw := range []string{"zz", "0"} {
		t.Run(raw, func(t *testing.T) {
			var err error
			require.NotPanics(t, func() {
				err = node.httpCreateBitcoinAccountRecoveryRequest(t.Context(), safe, raw, "hash")
			})
			require.Error(t, err)
			require.NotPanics(t, func() {
				_, err = node.httpCreateBitcoinInheritanceTransaction(t.Context(), safe, nil, "hash", raw)
			})
			require.Error(t, err)
		})
	}
}

func TestBitcoinProcessingRejectsMalformedOutputs(t *testing.T) {
	node := &Node{}
	for _, raw := range []string{
		`null`,
		`{"txid":"hash","vout":[null]}`,
		`{"txid":"hash","vout":[{}]}`,
		`{"txid":"hash","vout":[{"n":1,"scriptPubKey":{"type":"witness_v0_scripthash"}}]}`,
	} {
		t.Run(raw, func(t *testing.T) {
			var tx *bitcoin.RPCTransaction
			require.NoError(t, json.Unmarshal([]byte(raw), &tx))
			var err error
			require.NotPanics(t, func() { err = node.bitcoinProcessTransaction(t.Context(), tx, common.SafeChainBitcoin) })
			require.Error(t, err)
		})
	}
}

func TestBitcoinRecoveryRejectsMissingOutputsBeforeSignatureChecks(t *testing.T) {
	s := coverageObserverStore(t)
	node := &Node{store: s}
	for _, count := range []int{0, 1, 3} {
		msg := wire.NewMsgTx(2)
		msg.AddTxIn(&wire.TxIn{Sequence: 1})
		for range count {
			msg.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
		}
		packet, err := psbt.NewFromUnsignedTx(msg)
		require.NoError(t, err)
		tx := &bitcoin.PartiallySignedTransaction{Packet: packet}
		raw := hex.EncodeToString(tx.Marshal())
		err = node.httpCreateBitcoinAccountRecoveryRequest(t.Context(), &keeperstore.Safe{Holder: "holder"}, raw, tx.Hash())
		require.Error(t, err)
	}
}
