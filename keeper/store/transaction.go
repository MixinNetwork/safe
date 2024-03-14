package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/apps/mixin"
	"github.com/MixinNetwork/safe/common"
)

type Transaction struct {
	TransactionHash string
	RawTransaction  string
	Holder          string
	Chain           byte
	AssetId         string
	State           int
	Data            string
	RequestId       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type TransactionInput struct {
	Hash  string
	Index uint32
}

var transactionCols = []string{"transaction_hash", "raw_transaction", "holder", "chain", "asset_id", "state", "data", "request_id", "created_at", "updated_at"}

func TransactionInputsFromBitcoin(mainInputs []*bitcoin.Input) []*TransactionInput {
	inputs := make([]*TransactionInput, len(mainInputs))
	for i, in := range mainInputs {
		inputs[i] = &TransactionInput{
			Hash:  in.TransactionHash,
			Index: in.Index,
		}
	}
	return inputs
}

func TransactionInputsFromRawTransaction(trx *Transaction) []*TransactionInput {
	b := common.DecodeHexOrPanic(trx.RawTransaction)
	var inputs []*TransactionInput
	switch trx.Chain {
	case bitcoin.ChainBitcoin, bitcoin.ChainLitecoin:
		psbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)
		for _, in := range psbt.UnsignedTx.TxIn {
			pop := in.PreviousOutPoint
			inputs = append(inputs, &TransactionInput{
				Hash:  pop.Hash.String(),
				Index: pop.Index,
			})
		}
	case mixin.ChainMixinKernel:
		ver, _ := mixin.ParsePartiallySignedTransaction(b)
		for _, in := range ver.Inputs {
			inputs = append(inputs, &TransactionInput{
				Hash:  in.Hash.String(),
				Index: uint32(in.Index),
			})
		}
	default:
		panic(trx.Chain)
	}
	return inputs
}

func (s *SQLite3Store) ReadTransactionByRequestId(ctx context.Context, requestId string) (*Transaction, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var hash string
	query := "SELECT transaction_hash FROM transactions WHERE request_id=?"
	row := tx.QueryRowContext(ctx, query, requestId)
	err = row.Scan(&hash)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return s.readTransaction(ctx, tx, hash)
}

func (s *SQLite3Store) ReadTransaction(ctx context.Context, hash string) (*Transaction, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	return s.readTransaction(ctx, tx, hash)
}

func (s *SQLite3Store) CountUnfinishedTransactionsByHolder(ctx context.Context, holder string) (int, error) {
	query := "SELECT COUNT(*) FROM transactions WHERE holder=? AND state=?"
	row := s.db.QueryRowContext(ctx, query, holder, common.RequestStateInitial)

	var count int
	err := row.Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

func (s *SQLite3Store) ReadUnfinishedTransactionsByHolder(ctx context.Context, holder string) ([]*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions WHERE holder=? AND state IN (?, ?)", strings.Join(transactionCols, ","))
	rows, err := s.db.QueryContext(ctx, query, holder, common.RequestStateInitial, common.RequestStatePending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var txs []*Transaction
	for rows.Next() {
		var tx Transaction
		err = rows.Scan(&tx.TransactionHash, &tx.RawTransaction, &tx.Holder, &tx.Chain, &tx.AssetId, &tx.State, &tx.Data, &tx.RequestId, &tx.CreatedAt, &tx.UpdatedAt)
		if err != nil {
			return nil, err
		}
		txs = append(txs, &tx)
	}
	return txs, nil
}

func (s *SQLite3Store) CloseAccountByTransactionWithRequest(ctx context.Context, trx *Transaction, utxos []*TransactionInput, utxoState int) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existed, err := s.checkExistence(ctx, tx, "SELECT transaction_hash FROM transactions WHERE transaction_hash=?", trx.TransactionHash)
	if err != nil {
		return err
	}
	if !existed {
		err = s.execOne(ctx, tx, "UPDATE safes SET state=?, updated_at=? WHERE holder=? AND state=?",
			common.RequestStateFailed, trx.CreatedAt, trx.Holder, common.RequestStateDone)
		if err != nil {
			return fmt.Errorf("UPDATE safes %v", err)
		}

		err = s.writeTransactionWithRequest(ctx, tx, trx, utxos, utxoState)
		if err != nil {
			return err
		}
	} else {
		err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
			common.RequestStateDone, time.Now().UTC(), trx.RequestId)
		if err != nil {
			return fmt.Errorf("UPDATE requests %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) WriteInitialTransaction(ctx context.Context, trx *Transaction) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	vals := []any{trx.TransactionHash, trx.RawTransaction, trx.Holder, trx.Chain, trx.AssetId, trx.State, trx.Data, trx.RequestId, trx.CreatedAt, trx.UpdatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("transactions", transactionCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT transactions %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) UpdateInitialTransaction(ctx context.Context, hash, raw string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.execOne(ctx, tx, "UPDATE transactions SET raw_transaction=?, updated_at=? WHERE transaction_hash=?",
		raw, time.Now().UTC(), hash)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) WriteTransactionWithRequest(ctx context.Context, trx *Transaction, utxos []*TransactionInput) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.writeTransactionWithRequest(ctx, tx, trx, utxos, common.RequestStatePending)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite3Store) writeTransactionWithRequest(ctx context.Context, tx *sql.Tx, trx *Transaction, utxos []*TransactionInput, utxoState int) error {
	vals := []any{trx.TransactionHash, trx.RawTransaction, trx.Holder, trx.Chain, trx.AssetId, trx.State, trx.Data, trx.RequestId, trx.CreatedAt, trx.UpdatedAt}
	err := s.execOne(ctx, tx, buildInsertionSQL("transactions", transactionCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT transactions %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), trx.RequestId)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}
	table := transactionInputTable(trx.Chain)
	if table == "" {
		return nil
	}
	query := fmt.Sprintf("UPDATE %s SET state=?, spent_by=?, updated_at=? WHERE transaction_hash=? AND output_index=?", table)
	for _, utxo := range utxos {
		err = s.execOne(ctx, tx, query, utxoState, trx.TransactionHash, trx.UpdatedAt, utxo.Hash, utxo.Index)
		if err != nil {
			return fmt.Errorf("UPDATE %s %v", table, err)
		}
	}
	return nil
}

func (s *SQLite3Store) RevokeTransactionWithRequest(ctx context.Context, trx *Transaction, safe *Safe, req *common.Request) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if table := transactionInputTable(trx.Chain); table != "" {
		inputs := TransactionInputsFromRawTransaction(trx)
		update := fmt.Sprintf("UPDATE %s SET state=?, spent_by=?, updated_at=? WHERE transaction_hash=? AND output_index=? AND spent_by=?", table)
		query := fmt.Sprintf("SELECT address FROM %s WHERE transaction_hash=? AND output_index=?", table)
		for _, in := range inputs {
			err = s.execOne(ctx, tx, update, common.RequestStateInitial, nil, req.CreatedAt, in.Hash, in.Index, trx.TransactionHash)
			if err != nil {
				return fmt.Errorf("UPDATE %s %v", table, err)
			}

			var receiver string
			row := tx.QueryRowContext(ctx, query, in.Hash, in.Index)
			err = row.Scan(&receiver)
			if err != nil {
				return err
			}
			if receiver != safe.Address {
				panic(trx.TransactionHash)
			}
		}
	}

	err = s.execOne(ctx, tx, "UPDATE transactions SET state=?, updated_at=? WHERE transaction_hash=? AND state=?",
		common.RequestStateFailed, req.CreatedAt, trx.TransactionHash, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) FailTransactionWithRequest(ctx context.Context, trx *Transaction, safe *Safe, req *common.Request) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.execOne(ctx, tx, "UPDATE transactions SET state=?, updated_at=? WHERE transaction_hash=? AND state=?",
		common.RequestStateFailed, req.CreatedAt, trx.TransactionHash, common.RequestStateDone)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE safes SET nonce=?, updated_at=? WHERE holder=? AND nonce=? AND state=?",
		safe.Nonce-1, time.Now().UTC(), safe.Holder, safe.Nonce, common.RequestStateDone)
	if err != nil {
		return fmt.Errorf("UPDATE safes %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) readTransaction(ctx context.Context, tx *sql.Tx, transactionHash string) (*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions WHERE transaction_hash=?", strings.Join(transactionCols, ","))
	row := tx.QueryRowContext(ctx, query, transactionHash)

	var trx Transaction
	err := row.Scan(&trx.TransactionHash, &trx.RawTransaction, &trx.Holder, &trx.Chain, &trx.AssetId, &trx.State, &trx.Data, &trx.RequestId, &trx.CreatedAt, &trx.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &trx, err
}

func transactionInputTable(chain byte) string {
	switch chain {
	case bitcoin.ChainBitcoin, bitcoin.ChainLitecoin:
		return "bitcoin_outputs"
	case mixin.ChainMixinKernel:
		return "mixin_outputs"
	case ethereum.ChainEthereum, ethereum.ChainMVM, ethereum.ChainPolygon:
		return ""
	default:
		panic(chain)
	}
}
