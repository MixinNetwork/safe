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
	"github.com/MixinNetwork/safe/mtg"
)

func (s *SQLite3Store) WriteBitcoinOutputFromRequest(ctx context.Context, safe *Safe, utxo *bitcoin.Input, req *common.Request, assetId, sender string, txs []*mtg.Transaction) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	script := hex.EncodeToString(utxo.Script)
	cols := []string{"transaction_hash", "output_index", "address", "satoshi", "script", "sequence", "chain", "state", "spent_by", "request_id", "created_at", "updated_at"}
	vals := []any{utxo.TransactionHash, utxo.Index, safe.Address, utxo.Satoshi, script, utxo.Sequence, safe.Chain, common.RequestStateInitial, nil, req.Id, req.CreatedAt, req.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("bitcoin_outputs", cols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT bitcoin_outputs %v", err)
	}

	vals = []any{utxo.TransactionHash, utxo.Index, assetId, fmt.Sprint(utxo.Satoshi), safe.Address, sender, common.RequestStateDone, safe.Chain, safe.Holder, common.ActionObserverHolderDeposit, req.CreatedAt, req.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("deposits", depositsCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT deposits %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?", common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	err = s.writeActionResult(ctx, tx, req.Output.OutputId, "", txs, req.Id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite3Store) ReadBitcoinUTXO(ctx context.Context, transactionHash string, index int) (*bitcoin.Input, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer common.Rollback(tx)

	return s.readBitcoinUTXO(ctx, tx, transactionHash, index)
}

func (s *SQLite3Store) ListAllBitcoinUTXOsForHolder(ctx context.Context, holder string) ([]*bitcoin.Input, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer common.Rollback(tx)

	safe, err := s.readSafe(ctx, tx, holder)
	if err != nil {
		return nil, err
	}

	mainInputs, err := s.listAllBitcoinUTXOsForAddress(ctx, safe.Address, safe.Chain, common.RequestStateInitial)
	if err != nil {
		return nil, err
	}

	return mainInputs, nil
}

func (s *SQLite3Store) ListPendingBitcoinUTXOsForHolder(ctx context.Context, holder string) ([]*bitcoin.Input, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer common.Rollback(tx)

	safe, err := s.readSafe(ctx, tx, holder)
	if err != nil {
		return nil, err
	}

	mainInputs, err := s.listAllBitcoinUTXOsForAddress(ctx, safe.Address, safe.Chain, common.RequestStatePending)
	if err != nil {
		return nil, err
	}

	return mainInputs, nil
}

func (s *SQLite3Store) ReadUnspentUtxoCountForSafe(ctx context.Context, address string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer common.Rollback(tx)

	query := "SELECT COUNT(*) FROM bitcoin_outputs WHERE address=? AND state IN (?, ?)"
	row := s.db.QueryRowContext(ctx, query, address, common.RequestStateInitial, common.RequestStatePending)
	var count int
	err = row.Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

func (s *SQLite3Store) listAllBitcoinUTXOsForAddress(ctx context.Context, receiver string, chain byte, state int) ([]*bitcoin.Input, error) {
	cols := strings.Join([]string{"transaction_hash", "output_index", "satoshi", "script", "sequence"}, ",")
	query := fmt.Sprintf("SELECT %s FROM bitcoin_outputs WHERE address=? AND state=? ORDER BY created_at ASC, request_id ASC", cols)
	rows, err := s.db.QueryContext(ctx, query, receiver, state)
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
