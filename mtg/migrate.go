package mtg

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/gofrs/uuid/v5"
)

func (s *SQLite3Store) GetConsumedIds(ctx context.Context, tx *Transaction) error {
	if len(tx.consumedIds) > 0 {
		return nil
	}
	outputs, err := s.ListOutputsForTransaction(ctx, tx.TraceId, tx.Sequence)
	if err != nil {
		return err
	}
	for _, o := range outputs {
		tx.consumed = append(tx.consumed, o)
		tx.consumedIds = append(tx.consumedIds, o.OutputId)
	}
	return nil
}

func (s *SQLite3Store) Migrate(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(tx)

	key, val := "SCHEMA:VERSION:COMPUTER", ""
	row := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&val)
	if err == nil || err != sql.ErrNoRows {
		return err
	}

	nilId := uuid.Nil.String()
	query := fmt.Sprintf("ALTER TABLE transactions ADD COLUMN action_id VARCHAR NOT NULL DEFAULT '%s';\n", nilId)
	query = query + "ALTER TABLE transactions ADD COLUMN destination VARCHAR;\n"
	query = query + "ALTER TABLE transactions ADD COLUMN tag VARCHAR;\n"
	query = query + "ALTER TABLE transactions ADD COLUMN withdrawal_hash VARCHAR;\n"
	query = query + "CREATE INDEX IF NOT EXISTS transactions_by_state_sequence_hash ON transactions(state, sequence, hash);\n"
	query = query + "CREATE INDEX IF NOT EXISTS transactions_by_state_withdrawal_hash_updated ON transactions(state, withdrawal_hash, updated_at);\n"
	query = query + "DROP INDEX transactions_by_state_sequence;\n"
	query = query + "CREATE INDEX IF NOT EXISTS outputs_by_hash_sequence ON outputs(transaction_hash, sequence);\n"

	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, "INSERT INTO properties (key, value, created_at, updated_at) VALUES (?, ?, ?, ?)", key, query, now, now)
	if err != nil {
		return err
	}

	return tx.Commit()
}
