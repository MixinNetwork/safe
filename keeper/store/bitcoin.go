package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
)

func (s *SQLite3Store) WriteBitcoinOutputFromRequest(ctx context.Context, receiver string, utxo *bitcoin.Input, req *common.Request, chain byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	script := hex.EncodeToString(utxo.Script)
	cols := []string{"transaction_hash", "output_index", "address", "satoshi", "script", "sequence", "chain", "state", "spent_by", "request_id", "created_at", "updated_at"}
	vals := []any{utxo.TransactionHash, utxo.Index, receiver, utxo.Satoshi, script, utxo.Sequence, chain, common.RequestStateInitial, nil, req.Id, req.CreatedAt, req.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("bitcoin_outputs", cols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT bitcoin_outputs %v", err)
	}
	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?", common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) ReadBitcoinUTXO(ctx context.Context, transactionHash string, index int) (*bitcoin.Input, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()

	return s.readBitcoinUTXO(ctx, tx, transactionHash, index)
}

func (s *SQLite3Store) ListAllBitcoinUTXOsForHolder(ctx context.Context, holder string) ([]*bitcoin.Input, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	safe, err := s.readSafe(ctx, tx, holder)
	if err != nil {
		return nil, err
	}

	mainInputs, err := s.listAllBitcoinUTXOsForAddress(ctx, safe.Address, safe.Chain)
	if err != nil {
		return nil, err
	}

	return mainInputs, nil
}

func (s *SQLite3Store) listAllBitcoinUTXOsForAddress(ctx context.Context, receiver string, chain byte) ([]*bitcoin.Input, error) {
	cols := strings.Join([]string{"transaction_hash", "output_index", "satoshi", "script", "sequence"}, ",")
	query := fmt.Sprintf("SELECT %s FROM bitcoin_outputs WHERE address=? AND state=? ORDER BY created_at ASC, request_id ASC", cols)
	rows, err := s.db.QueryContext(ctx, query, receiver, common.RequestStateInitial)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var inputs []*bitcoin.Input
	for rows.Next() {
		var script string
		var input bitcoin.Input
		err = rows.Scan(&input.TransactionHash, &input.Index, &input.Satoshi, &script, &input.Sequence)
		if err != nil {
			return nil, err
		}
		input.Script = common.DecodeHexOrPanic(script)
		addr, err := bitcoin.EncodeAddress(input.Script, chain)
		if err != nil || receiver != addr {
			panic(receiver)
		}
		inputs = append(inputs, &input)
	}
	return inputs, nil
}

func (s *SQLite3Store) readBitcoinUTXO(ctx context.Context, tx *sql.Tx, transactionHash string, index int) (*bitcoin.Input, string, error) {
	input := &bitcoin.Input{
		TransactionHash: transactionHash,
		Index:           uint32(index),
	}

	query := "SELECT satoshi,script,sequence,spent_by FROM bitcoin_outputs WHERE transaction_hash=? AND output_index=?"
	row := tx.QueryRowContext(ctx, query, transactionHash, index)

	var script, spent sql.NullString
	err := row.Scan(&input.Satoshi, &script, &input.Sequence, &spent)
	if err == sql.ErrNoRows {
		return nil, "", nil
	} else if err != nil {
		return nil, "", err
	}
	input.Script = common.DecodeHexOrPanic(script.String)
	return input, spent.String, nil
}
