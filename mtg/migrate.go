package mtg

import (
	"context"
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

func (s *SQLite3Store) Migrate(ctx context.Context) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	query := "ALTER TABLE transactions ADD COLUMN action_id VARCHAR NOT NULL DEFAULT '';\n"
	query = query + "ALTER TABLE transactions ADD COLUMN destination VARCHAR;\n"
	query = query + "ALTER TABLE transactions ADD COLUMN tag VARCHAR;\n"
	query = query + "ALTER TABLE transactions ADD COLUMN withdrawal_hash VARCHAR;\n"
	query = query + "CREATE INDEX IF NOT EXISTS outputs_by_hash_sequence ON outputs(transaction_hash, sequence);\n"
	query = query + "CREATE INDEX IF NOT EXISTS transactions_by_state_sequence_hash ON transactions(state, sequence, hash);\n"
	query = query + "CREATE INDEX IF NOT EXISTS withdrawal_transactions_by_state_hash_updated ON transactions(state, withdrawal_hash,updated_at);\n"

	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		return "", err
	}

	return query, tx.Commit()
}
