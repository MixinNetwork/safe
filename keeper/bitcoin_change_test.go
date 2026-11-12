package keeper

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestBitcoinChangeWithFeeInputs(t *testing.T) {
	for _, chain := range []byte{common.SafeChainBitcoin, common.SafeChainLitecoin} {
		for _, recovery := range []bool{false, true} {
			for _, fees := range []int{0, 1, 2} {
				t.Run(fmt.Sprintf("chain-%d/recovery-%t/fee-inputs-%d", chain, recovery, fees), func(t *testing.T) {
					f := newBitcoinChangeFixture(t, chain, recovery)
					tx := f.withFeeInputs(t, fees)
					if fees > 0 {
						require.NotEqual(t, f.proposal.Hash(), tx.TxHash().String())
					}
					btx := bitcoinChangeRPCTransaction(t, tx, chain)
					for index, wantChange := range []bool{false, true} {
						change, err := f.node.checkBitcoinChange(t.Context(), &Deposit{
							Hash: btx.TxId, Index: uint64(index), Chain: chain,
						}, btx)
						require.NoError(t, err)
						require.Equal(t, wantChange, change, "recipient credit and sender change must remain distinct")
					}
				})
			}
		}
	}
}

func TestBitcoinChangeRejectsForeignAndUnfinishedSpends(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mutate       func(*wire.MsgTx)
		state        int
		clearSpender bool
	}{
		{name: "recipient changed", mutate: func(tx *wire.MsgTx) { tx.TxOut[0].PkScript = tx.TxOut[1].PkScript }},
		{name: "payment amount changed", mutate: func(tx *wire.MsgTx) { tx.TxOut[0].Value++ }},
		{name: "change amount changed", mutate: func(tx *wire.MsgTx) { tx.TxOut[1].Value-- }},
		{name: "request ID changed", mutate: func(tx *wire.MsgTx) { tx.TxOut[2].PkScript[2] ^= 1 }},
		{name: "output added", mutate: func(tx *wire.MsgTx) { tx.AddTxOut(wire.NewTxOut(1000, tx.TxOut[0].PkScript)) }},
		{name: "version changed", mutate: func(tx *wire.MsgTx) { tx.Version++ }},
		{name: "locktime changed", mutate: func(tx *wire.MsgTx) { tx.LockTime++ }},
		{name: "sequence changed", mutate: func(tx *wire.MsgTx) { tx.TxIn[0].Sequence-- }},
		{name: "input replaced", mutate: func(tx *wire.MsgTx) { tx.TxIn[0].PreviousOutPoint.Hash[0] ^= 1 }},
		{name: "input removed", mutate: func(tx *wire.MsgTx) { tx.TxIn = tx.TxIn[1:] }},
		{name: "inputs reordered", mutate: func(tx *wire.MsgTx) { tx.TxIn[0], tx.TxIn[1] = tx.TxIn[1], tx.TxIn[0] }},
		{name: "fee input prepended", mutate: func(tx *wire.MsgTx) { tx.TxIn[0], tx.TxIn[2] = tx.TxIn[2], tx.TxIn[0] }},
		{name: "unsigned proposal", state: common.RequestStateInitial},
		{name: "partially signed proposal", state: common.RequestStatePending},
		{name: "revoked proposal", state: common.RequestStateFailed, clearSpender: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBitcoinChangeFixture(t, common.SafeChainBitcoin, false)
			tx := f.withFeeInputs(t, 1)
			if tc.mutate != nil {
				tc.mutate(tx)
			}
			if tc.state != 0 {
				_, err := f.db.ExecContext(t.Context(), "UPDATE transactions SET state=?", tc.state)
				require.NoError(t, err)
			}
			if tc.clearSpender {
				_, err := f.db.ExecContext(t.Context(), "UPDATE bitcoin_outputs SET spent_by=NULL")
				require.NoError(t, err)
			}
			btx := bitcoinChangeRPCTransaction(t, tx, f.chain)
			change, err := f.node.checkBitcoinChange(t.Context(), &Deposit{Hash: btx.TxId, Index: 0, Chain: f.chain}, btx)
			require.NoError(t, err)
			require.True(t, change, "a foreign or refundable spend must not issue deposit credit")
		})
	}
}

func TestBitcoinChangeChecksAdditionalSafeInputs(t *testing.T) {
	f := newBitcoinChangeFixture(t, common.SafeChainBitcoin, false)
	tx := f.withFeeInputs(t, 1)
	fee := tx.TxIn[2].PreviousOutPoint
	// Even if the original proposal matches, an additional input belonging
	// to another safe cannot be treated as an ordinary accountant fee input.
	_, err := f.db.ExecContext(t.Context(), `INSERT INTO bitcoin_outputs
		(transaction_hash,output_index,address,satoshi,script,sequence,chain,state,spent_by,request_id,created_at,updated_at)
		SELECT ?,?,address,satoshi,script,sequence,chain,state,NULL,'other-safe',created_at,updated_at FROM bitcoin_outputs LIMIT 1`,
		fee.Hash.String(), fee.Index)
	require.NoError(t, err)
	btx := bitcoinChangeRPCTransaction(t, tx, f.chain)
	change, err := f.node.checkBitcoinChange(t.Context(), &Deposit{Hash: btx.TxId, Index: 0, Chain: f.chain}, btx)
	require.NoError(t, err)
	require.True(t, change)
}

func TestBitcoinChangeAcceptsExternalDeposit(t *testing.T) {
	f := newBitcoinChangeFixture(t, common.SafeChainBitcoin, false)
	tx := f.signed.Copy()
	for _, input := range tx.TxIn {
		input.PreviousOutPoint.Hash[0] ^= 1
	}
	btx := bitcoinChangeRPCTransaction(t, tx, f.chain)
	change, err := f.node.checkBitcoinChange(t.Context(), &Deposit{Hash: btx.TxId, Index: 0, Chain: f.chain}, btx)
	require.NoError(t, err)
	require.False(t, change, "inputs unrelated to any safe remain external deposits")
}

func TestBitcoinChangeRejectsInconsistentRawTransaction(t *testing.T) {
	for _, tc := range []string{"different hash", "different inputs"} {
		t.Run(tc, func(t *testing.T) {
			f := newBitcoinChangeFixture(t, common.SafeChainBitcoin, false)
			btx := bitcoinChangeRPCTransaction(t, f.withFeeInputs(t, 1), f.chain)
			switch tc {
			case "different hash":
				btx.TxId = strings.Repeat("f", 64)
			case "different inputs":
				btx.Vin = btx.Vin[:2]
			}
			_, err := f.node.checkBitcoinChange(t.Context(), &Deposit{Hash: btx.TxId, Index: 0, Chain: f.chain}, btx)
			require.Error(t, err)
		})
	}
}

type bitcoinChangeFixture struct {
	node     *Node
	db       *sql.DB
	chain    byte
	proposal *bitcoin.PartiallySignedTransaction
	signed   *wire.MsgTx
}

func newBitcoinChangeFixture(t *testing.T, chain byte, recovery bool) *bitcoinChangeFixture {
	t.Helper()
	keys := make([]*btcec.PrivateKey, 6)
	pubs := make([]string, len(keys))
	for i := range keys {
		keys[i], _ = btcec.PrivKeyFromBytes([]byte{byte(i + 1)})
		pubs[i] = hex.EncodeToString(keys[i].PubKey().SerializeCompressed())
	}
	sender, err := bitcoin.BuildWitnessScriptAccount(pubs[0], pubs[1], pubs[2], 48*time.Hour, chain)
	require.NoError(t, err)
	receiver, err := bitcoin.BuildWitnessScriptAccount(pubs[3], pubs[4], pubs[5], 48*time.Hour, chain)
	require.NoError(t, err)
	inputs := []*bitcoin.Input{
		{TransactionHash: strings.Repeat("1", 64), Satoshi: 20000, Script: sender.Script, Sequence: sender.Sequence, RouteBackup: recovery},
		{TransactionHash: strings.Repeat("2", 64), Satoshi: 30000, Script: sender.Script, Sequence: sender.Sequence, RouteBackup: recovery},
	}
	id := uuid.Must(uuid.NewV4())
	proposal, err := bitcoin.BuildPartiallySignedTransaction(inputs, []*bitcoin.Output{{Address: receiver.Address, Satoshi: 20000}}, id.Bytes(), chain)
	require.NoError(t, err)
	cosigner := keys[0]
	if recovery {
		cosigner = keys[2]
	}
	proposal = bitcoin.SignPartiallySignedTransaction(proposal.Marshal(), cosigner)
	proposal = bitcoin.SignPartiallySignedTransaction(proposal.Marshal(), keys[1])
	signed, err := proposal.SignedTransaction(pubs[0], pubs[1], pubs[2])
	require.NoError(t, err)
	path := t.TempDir() + "/keeper.sqlite3"
	db, err := common.OpenSQLite3Store(path, store.SCHEMA)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	s, err := store.OpenSQLite3Store(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	now := time.Now().UTC()
	for i, input := range inputs {
		_, err = db.ExecContext(t.Context(), `INSERT INTO bitcoin_outputs
			(transaction_hash,output_index,address,satoshi,script,sequence,chain,state,spent_by,request_id,created_at,updated_at)
			VALUES (?,0,?,?,?,?,?,?,?,?,?,?)`, input.TransactionHash, sender.Address, input.Satoshi,
			hex.EncodeToString(sender.Script), sender.Sequence, chain, common.RequestStateDone, proposal.Hash(), fmt.Sprint(i), now, now)
		require.NoError(t, err)
	}
	data := common.MarshalJSONOrPanic([]map[string]string{{"receiver": receiver.Address, "amount": "0.0002"}})
	_, err = db.ExecContext(t.Context(), `INSERT INTO transactions
		(transaction_hash,raw_transaction,holder,chain,asset_id,state,data,request_id,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`, proposal.Hash(), hex.EncodeToString(proposal.Marshal()), pubs[0], chain,
		common.SafeChainAssetId(chain), common.RequestStateDone, string(data), id.String(), now, now)
	require.NoError(t, err)
	return &bitcoinChangeFixture{node: &Node{store: s}, db: db, chain: chain, proposal: proposal, signed: signed}
}

func (f *bitcoinChangeFixture) withFeeInputs(t *testing.T, count int) *wire.MsgTx {
	t.Helper()
	if count == 0 {
		return f.signed.Copy()
	}
	var fees []*bitcoin.Input
	for i := range count {
		fees = append(fees, &bitcoin.Input{TransactionHash: fmt.Sprintf("%064x", i+100), Satoshi: 1000})
	}
	raw, err := bitcoin.MarshalWiredTransaction(f.signed, wire.WitnessEncoding, f.chain)
	require.NoError(t, err)
	tx, err := bitcoin.SpendSignedTransaction(hex.EncodeToString(raw), fees, strings.Repeat("01", 32), f.chain)
	require.NoError(t, err)
	return tx
}

func bitcoinChangeRPCTransaction(t *testing.T, tx *wire.MsgTx, chain byte) *bitcoin.RPCTransaction {
	t.Helper()
	var inputs []map[string]any
	for _, input := range tx.TxIn {
		inputs = append(inputs, map[string]any{"txid": input.PreviousOutPoint.Hash.String(), "vout": input.PreviousOutPoint.Index})
	}
	raw, err := bitcoin.MarshalWiredTransaction(tx, wire.WitnessEncoding, chain)
	require.NoError(t, err)
	payload := common.MarshalJSONOrPanic(map[string]any{"txid": tx.TxHash().String(), "vin": inputs, "hex": hex.EncodeToString(raw)})
	var result bitcoin.RPCTransaction
	require.NoError(t, json.Unmarshal(payload, &result))
	return &result
}
