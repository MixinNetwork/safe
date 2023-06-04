package observer

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (node *Node) bitcoinCombileTransactionSignatures(ctx context.Context, extra []byte) error {
	spsbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(extra)

	tx, err := node.store.ReadTransactionApproval(ctx, spsbt.Hash())
	if err != nil || tx.State == common.RequestStateDone {
		return err
	}
	switch tx.Chain {
	case keeper.SafeChainBitcoin:
	case keeper.SafeChainLitecoin:
	default:
		panic(spsbt.Hash())
	}
	b := common.DecodeHexOrPanic(tx.RawTransaction)
	hpsbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)

	requests, err := node.keeperStore.ListAllSignaturesForTransaction(ctx, spsbt.Hash(), common.RequestStateDone)
	if err != nil {
		return err
	}
	signed := make(map[int][]byte)
	for _, r := range requests {
		signed[r.InputIndex] = common.DecodeHexOrPanic(r.Signature.String)
	}

	msgTx := spsbt.UnsignedTx
	for idx := range msgTx.TxIn {
		pop := msgTx.TxIn[idx].PreviousOutPoint
		hash := spsbt.SigHash(idx)
		utxo, _ := node.keeperStore.ReadBitcoinUTXO(ctx, pop.Hash.String(), int(pop.Index))
		required := node.checkBitcoinUTXOSignatureRequired(ctx, pop)
		if !required {
			continue
		}
		hpin := hpsbt.Inputs[idx]
		hsig := hpin.PartialSigs[0]
		if hex.EncodeToString(hsig.PubKey) != tx.Holder {
			panic(spsbt.Hash())
		}

		spin := spsbt.Inputs[idx]
		ssig := spin.PartialSigs[0]
		if hex.EncodeToString(ssig.PubKey) != tx.Signer {
			panic(spsbt.Hash())
		}
		if !bytes.Equal(ssig.Signature, signed[idx]) {
			panic(spsbt.Hash())
		}
		der, _ := ecdsa.ParseDERSignature(ssig.Signature)
		pub := common.DecodeHexOrPanic(tx.Signer)
		signer, _ := btcutil.NewAddressPubKey(pub, &chaincfg.MainNetParams)
		if !der.Verify(hash, signer.PubKey()) {
			panic(spsbt.Hash())
		}

		sig := append(ssig.Signature, byte(bitcoin.SigHashType))
		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, []byte{})
		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)
		sig = append(hsig.Signature, byte(bitcoin.SigHashType))
		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)
		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, utxo.Script)

		hpsbt.Inputs[idx].PartialSigs = append(hpin.PartialSigs, spin.PartialSigs...)
	}

	raw := hex.EncodeToString(hpsbt.Marshal())
	err = node.store.FinishTransactionSignatures(ctx, spsbt.Hash(), raw)
	logger.Printf("store.FinishTransactionSignatures(%s) => %v", spsbt.Hash(), err)
	return err
}

func (node *Node) bitcoinTransactionSpendLoop(ctx context.Context, chain byte) {
	for {
		time.Sleep(3 * time.Second)
		txs, err := node.store.ListFullySignedTransactionApprovals(ctx, chain)
		if err != nil {
			panic(err)
		}
		for _, tx := range txs {
			spentHash, err := node.bitcoinSpendFullySignedTransaction(ctx, tx)
			if err != nil {
				panic(err)
			}
			err = node.store.ConfirmFullySignedTransactionApproval(ctx, tx.TransactionHash, spentHash)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) bitcoinSpendFullySignedTransaction(ctx context.Context, tx *Transaction) (string, error) {
	rpc, _ := node.bitcoinParams(tx.Chain)
	b := common.DecodeHexOrPanic(tx.RawTransaction)
	psbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)
	var signedBuffer bytes.Buffer
	err := psbt.UnsignedTx.BtcEncode(&signedBuffer, wire.ProtocolVersion, wire.WitnessEncoding)
	if err != nil {
		return "", err
	}

	weight := blockchain.GetTransactionWeight(btcutil.NewTx(psbt.UnsignedTx))
	virtualSize := (weight + 300) / 4
	info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, tx.Chain)
	if err != nil {
		return "", err
	}
	if info.CreatedAt.Add(keeper.SafeNetworkInfoTimeout).Before(time.Now()) {
		return "", fmt.Errorf("network info timeout %v", info)
	}
	fvb, err := bitcoin.RPCEstimateSmartFee(tx.Chain, rpc)
	if err != nil {
		return "", err
	}
	if uint64(fvb) > info.Fee {
		info.Fee = uint64(fvb)
	}
	fee := info.Fee * uint64(virtualSize)

	feeInput, err := node.bitcoinRetrieveFeeInputsForTransaction(ctx, fee, info.Fee, tx)
	if err != nil {
		return "", err
	}
	if feeInput == nil {
		return "", fmt.Errorf("insufficient accountant balance %d %d", fee, info.Fee)
	}

	accountant, err := node.store.ReadAccountantPrivateKey(ctx, feeInput.Address)
	if err != nil {
		return "", err
	}
	feeInputs := []*bitcoin.Input{{
		TransactionHash: feeInput.TransactionHash,
		Index:           feeInput.Index,
		Satoshi:         feeInput.Satoshi,
	}}
	msgTx, err := bitcoin.SpendSignedTransaction(hex.EncodeToString(signedBuffer.Bytes()), feeInputs, accountant, tx.Chain)
	if err != nil {
		return "", err
	}

	return "", node.bitcoinBroadcastTransactionAndWriteDeposit(ctx, feeInput, msgTx, tx.Chain)
}

func (node *Node) bitcoinRetrieveFeeInputsForTransaction(ctx context.Context, fee, fvb uint64, tx *Transaction) (*Output, error) {
	min, max := uint64(float64(fee)*0.9), uint64(float64(fee)*1.1)
	old, err := node.store.AssignBitcoinUTXOByRangeForTransaction(ctx, min, max, tx)
	if err != nil || old != nil {
		return old, err
	}

	utxos, err := node.store.ReadBitcoinUTXOs(ctx, tx.Chain)
	if err != nil || len(utxos) == 0 {
		return nil, err
	}

	receiver, total := utxos[0].Address, uint64(0)
	script, err := bitcoin.ParseAddress(receiver, tx.Chain)
	if err != nil {
		return nil, err
	}

	msgTx := wire.NewMsgTx(2)
	for _, utxo := range utxos {
		total = total + uint64(utxo.Satoshi)
		hash, err := chainhash.NewHashFromStr(utxo.TransactionHash)
		if err != nil {
			return nil, err
		}
		txIn := &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *hash,
				Index: utxo.Index,
			},
			Sequence: bitcoin.MaxTransactionSequence,
		}
		msgTx.AddTxIn(txIn)

		estvb := uint64(40+len(msgTx.TxIn)*300+2*128) / 4
		if total < estvb*fvb+fee {
			continue
		}

		out := wire.NewTxOut(int64(fee), script)
		msgTx.AddTxOut(out)
		change := total - estvb*fvb - fee
		if change > bitcoin.ValueDust {
			out := wire.NewTxOut(int64(change), script)
			msgTx.AddTxOut(out)
		}
	}
	if len(msgTx.TxOut) == 0 {
		return nil, nil
	}

	for idx := range msgTx.TxIn {
		in := utxos[idx]
		accountant, err := node.store.ReadAccountantPrivateKey(ctx, in.Address)
		if err != nil {
			return nil, err
		}
		b := common.DecodeHexOrPanic(accountant)
		privateKey, publicKey := btcec.PrivKeyFromBytes(b)

		script := publicKey.SerializeCompressed()
		script = btcutil.Hash160(script)
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_0)
		builder.AddData(script)
		script, err = builder.Script()
		if err != nil {
			return nil, err
		}
		pof := txscript.NewCannedPrevOutputFetcher(script, in.Satoshi)
		tsh := txscript.NewTxSigHashes(msgTx, pof)
		hash, err := txscript.CalcWitnessSigHash(script, tsh, txscript.SigHashAll, msgTx, idx, in.Satoshi)
		if err != nil {
			return nil, err
		}
		signature := ecdsa.Sign(privateKey, hash)
		sig := append(signature.Serialize(), byte(txscript.SigHashAll))
		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)
		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, publicKey.SerializeCompressed())
	}

	var signedBuffer bytes.Buffer
	err = msgTx.BtcEncode(&signedBuffer, wire.ProtocolVersion, wire.WitnessEncoding)
	if err != nil {
		return nil, err
	}
	hash := msgTx.TxHash().String()
	raw := signedBuffer.Bytes()

	return &Output{
		TransactionHash: hash,
		Index:           0,
		Satoshi:         msgTx.TxOut[0].Value,
		RawTransaction:  sql.NullString{Valid: true, String: hex.EncodeToString(raw)},
	}, node.store.WriteBitcoinFeeOutput(ctx, msgTx, receiver, tx)
}

func (s *SQLite3Store) ReadAccountantPrivateKey(ctx context.Context, address string) (string, error) {
	query := "SELECT private_key FROM accountants WHERE address=?"
	row := s.db.QueryRowContext(ctx, query, address)

	var key string
	err := row.Scan(&key)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return key, err
}

func (s *SQLite3Store) AssignBitcoinUTXOByRangeForTransaction(ctx context.Context, min, max uint64, tx *Transaction) (*Output, error) {
	txn, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer txn.Rollback()

	query := fmt.Sprintf("SELECT %s FROM bitcoin_outputs WHERE (chain=? AND satoshi>=? AND satoshi<=? AND state=?) OR (spent_by=?) LIMIT 1", strings.Join(outputCols, ","))
	params := []any{tx.Chain, min, max, common.RequestStateInitial, tx.TransactionHash}
	row := txn.QueryRowContext(ctx, query, params...)

	var o Output
	err = row.Scan(&o.TransactionHash, &o.Index, &o.Address, &o.Satoshi, &o.Chain, &o.State, &o.SpentBy, &o.RawTransaction, &o.CreatedAt, &o.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	err = s.execOne(ctx, txn, "UPDATE bitcoin_outputs SET state=?,spent_by=?,updated_at=? WHERE transaction_hash=? AND output_index=? AND state=? AND spent_by IS NULL",
		common.RequestStateDone, tx.TransactionHash, time.Now().UTC(), o.TransactionHash, o.Index)
	if err != nil {
		return nil, fmt.Errorf("UPDATE bitcoin_outputs %v", err)
	}
	return &o, txn.Commit()
}

func (s *SQLite3Store) ReadBitcoinUTXO(ctx context.Context, hash string, index int64, chain byte) (*Output, error) {
	query := fmt.Sprintf("SELECT %s FROM bitcoin_outputs WHERE chain=? AND transaction_hash=? AND output_index=?", strings.Join(outputCols, ","))
	row := s.db.QueryRowContext(ctx, query, chain, hash, index)

	var o Output
	err := row.Scan(&o.TransactionHash, &o.Index, &o.Address, &o.Satoshi, &o.Chain, &o.State, &o.SpentBy, &o.RawTransaction, &o.CreatedAt, &o.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &o, err
}

func (s *SQLite3Store) WriteBitcoinUTXO(ctx context.Context, utxo *Output) error {
	txn, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer txn.Rollback()

	err = s.execOne(ctx, txn, buildInsertionSQL("bitcoin_outputs", outputCols), utxo.values()...)
	if err != nil {
		return fmt.Errorf("INSERT bitcoin_outputs %v", err)
	}
	return txn.Commit()
}

func (s *SQLite3Store) ReadBitcoinUTXOs(ctx context.Context, chain byte) ([]*Output, error) {
	query := fmt.Sprintf("SELECT %s FROM bitcoin_outputs WHERE chain=? AND state=? ORDER BY created_at ASC LIMIT 256", strings.Join(outputCols, ","))
	params := []any{chain, common.RequestStateInitial}
	rows, err := s.db.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var outputs []*Output
	for rows.Next() {
		var o Output
		err := rows.Scan(&o.TransactionHash, &o.Index, &o.Address, &o.Satoshi, &o.Chain, &o.State, &o.SpentBy, &o.RawTransaction, &o.CreatedAt, &o.UpdatedAt)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, &o)
	}
	return outputs, nil
}

func (s *SQLite3Store) WriteBitcoinFeeOutput(ctx context.Context, msgTx *wire.MsgTx, receiver string, tx *Transaction) error {
	txn, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer txn.Rollback()

	var signedBuffer bytes.Buffer
	err = msgTx.BtcEncode(&signedBuffer, wire.ProtocolVersion, wire.WitnessEncoding)
	if err != nil {
		return err
	}
	hash := msgTx.TxHash().String()
	raw := hex.EncodeToString(signedBuffer.Bytes())

	for _, in := range msgTx.TxIn {
		err = s.execOne(ctx, txn, "UPDATE bitcoin_outputs SET state=?,spent_by=?,updated_at=? WHERE transaction_hash=? AND output_index=? AND state=? AND spent_by IS NULL",
			common.RequestStateDone, hash, time.Now().UTC(), in.PreviousOutPoint.Hash.String(), in.PreviousOutPoint.Index, common.RequestStateInitial)
		if err != nil {
			return fmt.Errorf("UPDATE bitcoin_outputs %v", err)
		}
	}
	for i, out := range msgTx.TxOut {
		utxo := &Output{
			TransactionHash: hash,
			Index:           uint32(i),
			Address:         receiver,
			Satoshi:         out.Value,
			Chain:           tx.Chain,
			State:           common.RequestStateInitial,
			RawTransaction:  sql.NullString{Valid: true, String: raw},
			CreatedAt:       time.Now().UTC(),
			UpdatedAt:       time.Now().UTC(),
		}
		if i == 0 {
			utxo.State = common.RequestStateDone
			utxo.SpentBy = sql.NullString{Valid: true, String: tx.TransactionHash}
		}
		err = s.execOne(ctx, txn, buildInsertionSQL("bitcoin_outputs", outputCols), utxo.values()...)
		if err != nil {
			return fmt.Errorf("INSERT bitcoin_outputs %v", err)
		}
	}
	return txn.Commit()
}

func (node *Node) bitcoinBroadcastTransactionAndWriteDeposit(ctx context.Context, feeInput *Output, msgTx *wire.MsgTx, chain byte) error {
	rpc, _ := node.bitcoinParams(chain)

	if feeInput.RawTransaction.String != "" {
		hash := feeInput.TransactionHash
		raw := common.DecodeHexOrPanic(feeInput.RawTransaction.String)
		err := node.bitcoinBroadcastTransaction(hash, raw, chain)
		if err != nil {
			return fmt.Errorf("node.bitcoinBroadcastTransaction(%s, %x) => %v", hash, raw, err)
		}
		tx, err := bitcoin.RPCGetTransaction(chain, rpc, hash)
		if err != nil || tx == nil {
			return fmt.Errorf("bitcoin.RPCGetTransaction(%s) => %v %v", hash, tx, err)
		}
	}

	var signedBuffer bytes.Buffer
	err := msgTx.BtcEncode(&signedBuffer, wire.ProtocolVersion, wire.WitnessEncoding)
	if err != nil {
		return err
	}
	hash := msgTx.TxHash().String()
	raw := signedBuffer.Bytes()
	err = node.bitcoinBroadcastTransaction(hash, raw, chain)
	if err != nil {
		return fmt.Errorf("node.bitcoinBroadcastTransaction(%s, %x) => %v", hash, raw, err)
	}
	tx, err := bitcoin.RPCGetTransaction(chain, rpc, hash)
	if err != nil || tx == nil {
		return fmt.Errorf("bitcoin.RPCGetTransaction(%s) => %v %v", hash, tx, err)
	}
	return node.bitcoinProcessTransaction(ctx, tx, chain)
}

func (node *Node) bitcoinBroadcastTransaction(hash string, raw []byte, chain byte) error {
	rpc, _ := node.bitcoinParams(chain)
	id, err := bitcoin.RPCSendRawTransaction(rpc, hex.EncodeToString(raw))
	if err != nil {
		return err
	}
	if id != hash {
		return fmt.Errorf("malformed bitcoin transaction %s %s", hash, id)
	}
	return nil
}
