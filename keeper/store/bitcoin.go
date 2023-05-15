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
	"github.com/shopspring/decimal"
)

func (s *SQLite3Store) WriteBitcoinOutputFromRequest(ctx context.Context, receiver string, utxo *bitcoin.Input, req *common.Request, isAccountant bool) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if isAccountant {
		feeBalance, err := s.readAccountantBalance(ctx, tx, req.Holder)
		if err != nil {
			return err
		}
		fee := decimal.New(utxo.Satoshi, -bitcoin.ValuePrecision)
		feeBalance = feeBalance.Add(fee)
		err = s.execOne(ctx, tx, "UPDATE accountants SET balance=?, updated_at=? WHERE holder=?", feeBalance, req.CreatedAt, req.Holder)
		if err != nil {
			return fmt.Errorf("UPDATE accountants %v", err)
		}
	}

	script := hex.EncodeToString(utxo.Script)
	cols := []string{"transaction_hash", "output_index", "public_key", "satoshi", "script", "sequence", "state", "spent_by", "request_id", "created_at", "updated_at"}
	vals := []any{utxo.TransactionHash, utxo.Index, receiver, utxo.Satoshi, script, utxo.Sequence, common.RequestStateInitial, nil, req.Id, req.CreatedAt, req.CreatedAt}
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

func (s *SQLite3Store) ReadBitcoinUTXO(ctx context.Context, transactionHash string, index int) (*bitcoin.Input, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	return s.readBitcoinUTXO(ctx, tx, transactionHash, index)
}

func (s *SQLite3Store) ListAllBitcoinUTXOsForHolder(ctx context.Context, holder string) ([]*bitcoin.Input, []*bitcoin.Input, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	safe, err := s.readSafe(ctx, tx, holder)
	if err != nil {
		return nil, nil, err
	}
	wka, err := bitcoin.BuildWitnessKeyAccount(safe.Accountant, safe.Chain)
	if err != nil {
		return nil, nil, err
	}

	mainInputs, err := s.listAllBitcoinUTXOsForPublicKey(ctx, safe.Address, safe.Chain)
	if err != nil {
		return nil, nil, err
	}
	feeInputs, err := s.listAllBitcoinUTXOsForPublicKey(ctx, wka.Address, safe.Chain)
	if err != nil {
		return nil, nil, err
	}

	return mainInputs, feeInputs, nil
}

func (s *SQLite3Store) listAllBitcoinUTXOsForPublicKey(ctx context.Context, public string, chain byte) ([]*bitcoin.Input, error) {
	cols := strings.Join([]string{"transaction_hash", "output_index", "satoshi", "script", "sequence"}, ",")
	query := fmt.Sprintf("SELECT %s FROM bitcoin_outputs WHERE public_key=? AND state=? ORDER BY created_at ASC", cols)
	rows, err := s.db.QueryContext(ctx, query, public, common.RequestStateInitial)
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
		if err != nil || public != addr {
			panic(public)
		}
		inputs = append(inputs, &input)
	}
	return inputs, nil
}

func (s *SQLite3Store) readBitcoinUTXO(ctx context.Context, tx *sql.Tx, transactionHash string, index int) (*bitcoin.Input, error) {
	input := &bitcoin.Input{
		TransactionHash: transactionHash,
		Index:           uint32(index),
	}

	query := "SELECT satoshi,script,sequence FROM bitcoin_outputs WHERE transaction_hash=? AND output_index=?"
	row := tx.QueryRowContext(ctx, query, transactionHash, index)

	var script string
	err := row.Scan(&input.Satoshi, &script, &input.Sequence)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	input.Script = common.DecodeHexOrPanic(script)
	return input, nil
}
