package bitcoin

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestBitcoinMultiRecipientTransactionSize(t *testing.T) {
	keys := make([]*btcec.PrivateKey, 3)
	public := make([]string, len(keys))
	for i := range keys {
		keys[i], _ = btcec.PrivKeyFromBytes([]byte{byte(i + 1)})
		public[i] = hex.EncodeToString(keys[i].PubKey().SerializeCompressed())
	}
	for _, chain := range []byte{ChainBitcoin, ChainLitecoin} {
		account, err := BuildWitnessScriptAccount(public[0], public[1], public[2], TimeLockMaximum, chain)
		require.NoError(t, err)
		pkScript, err := ParseAddress(account.Address, chain)
		require.NoError(t, err)
		wpkh, err := address.NewAddressWitnessPubKeyHash(address.Hash160(keys[0].PubKey().SerializeCompressed()), NetConfig(chain))
		require.NoError(t, err)
		for _, route := range []struct {
			name    string
			backup  bool
			signers []int
		}{
			{"normal", false, []int{0, 1}},
			{"recovery holder", true, []int{0, 2}},
			{"recovery signer", true, []int{1, 2}},
		} {
			for _, test := range []struct {
				name       string
				recipients int
				change     int64
				ridSize    int
				mixed      bool
			}{
				{"six recipients", 6, 0, 16, false},
				{"six recipients with change", 6, ValueDust(chain) + 1, 16, false},
				{"maximum return data", 6, 0, 64, false},
				{"small output count encoding", 252, 0, 0, false},
				{"large output count encoding", 253, 0, 0, false},
				{"mixed recipients", 256, ValueDust(chain) + 1, 16, true},
			} {
				t.Run(fmt.Sprintf("%d/%s/%s", chain, route.name, test.name), func(t *testing.T) {
					outputs := make([]*Output, test.recipients)
					for i := range outputs {
						receiver := account.Address
						if test.mixed && i%2 == 0 {
							receiver = wpkh.EncodeAddress()
						}
						outputs[i] = &Output{Address: receiver, Satoshi: 10_000}
					}
					input := &Input{
						TransactionHash: "01",
						Satoshi:         int64(test.recipients)*10_000 + test.change,
						Script:          account.Script,
						Sequence:        account.Sequence,
						RouteBackup:     route.backup,
					}
					packet, err := BuildPartiallySignedTransaction([]*Input{input}, outputs, make([]byte, test.ridSize), chain)
					require.NoError(t, err)
					count := test.recipients
					if test.change > 0 {
						count++
						require.Equal(t, wire.NewTxOut(test.change, pkScript), packet.UnsignedTx.TxOut[test.recipients])
					}
					if test.ridSize > 0 {
						count++
						require.Equal(t, byte(txscript.OP_RETURN), packet.UnsignedTx.TxOut[count-1].PkScript[0])
					}
					require.Len(t, packet.UnsignedTx.TxOut, count)
					for i, out := range outputs {
						script, err := ParseAddress(out.Address, chain)
						require.NoError(t, err)
						require.Equal(t, wire.NewTxOut(out.Satoshi, script), packet.UnsignedTx.TxOut[i])
					}
					estimate := packet.EstimateVirtualSize()
					for _, i := range route.signers {
						packet = SignPartiallySignedTransaction(packet.Marshal(), keys[i])
					}
					signed, err := packet.SignedTransaction(public[0], public[1], public[2])
					require.NoError(t, err)
					require.NoError(t, securityTestExecuteBitcoinInput(signed, 0, pkScript, input.Satoshi))
					actual := int(mempool.GetTxVirtualSize(btcutil.NewTx(signed)))
					require.GreaterOrEqual(t, estimate, actual)
					require.InDelta(t, actual, estimate, 2)
				})
			}
		}
	}
}

func TestBitcoinTransactionWeightLimit(t *testing.T) {
	public := make([]string, 3)
	for i := range public {
		_, key := btcec.PrivKeyFromBytes([]byte{byte(i + 1)})
		public[i] = hex.EncodeToString(key.SerializeCompressed())
	}
	for _, chain := range []byte{ChainBitcoin, ChainLitecoin} {
		account, err := BuildWitnessScriptAccount(public[0], public[1], public[2], TimeLockMaximum, chain)
		require.NoError(t, err)
		pkScript, err := ParseAddress(account.Address, chain)
		require.NoError(t, err)
		for _, inputCount := range []int{1, MaxUnspentUtxo} {
			t.Run(fmt.Sprintf("%d/%d inputs", chain, inputCount), func(t *testing.T) {
				// Build a reference transaction with maximum-sized signatures so
				// the limit includes witness bytes, marker/flag and count encodings.
				ref := wire.NewMsgTx(2)
				for i := range inputCount {
					ref.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{1}, uint32(i)), nil,
						wire.TxWitness{nil, make([]byte, 73), make([]byte, 73), account.Script}))
				}
				for blockchain.GetTransactionWeight(btcutil.NewTx(ref)) <= MaxStandardTxWeight {
					ref.AddTxOut(wire.NewTxOut(10_000, pkScript))
				}
				maxOutputs := len(ref.TxOut) - 1
				for _, count := range []int{maxOutputs, maxOutputs + 1} {
					outputs := make([]*Output, count)
					for i := range outputs {
						outputs[i] = &Output{Address: account.Address, Satoshi: 10_000}
					}
					inputs := make([]*Input, inputCount)
					for i := range inputs {
						inputs[i] = &Input{TransactionHash: "01", Index: uint32(i), Satoshi: 1, Script: account.Script}
					}
					inputs[0].Satoshi += int64(count)*10_000 - int64(inputCount)
					packet, err := BuildPartiallySignedTransaction(inputs, outputs, nil, chain)
					if count > maxOutputs {
						require.ErrorContains(t, err, "large")
						require.Nil(t, packet)
					} else {
						require.NoError(t, err)
						require.LessOrEqual(t, packet.EstimateVirtualSize()*blockchain.WitnessScaleFactor, MaxStandardTxWeight)
					}
				}
			})
		}
	}
}
