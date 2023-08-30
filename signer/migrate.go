package signer

import (
	"context"
	"database/sql"
	"time"
)

// FIXME remove this
func (s *SQLite3Store) migrate(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existed, err := s.checkExistence(ctx, tx, "SELECT session_id FROM sessions LIMIT 1")
	if err != nil || !existed {
		return err
	}

	key, val := "SCHEMA:VERSION:20230830", ""
	row := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&val)
	if err == nil || err != sql.ErrNoRows {
		return err
	}

	query := "ALTER TABLE sessions ADD COLUMN committed_at TIMESTAMP;\n"
	query = query + "ALTER TABLE sessions ADD COLUMN prepared_at TIMESTAMP;\n"
	query = query + "ALTER TABLE session_signers ADD COLUMN updated_at TIMESTAMP;"
	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, "UPDATE sessions SET committed_at=?, prepared_at=?", now, now)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE session_signers SET updated_at=?", now)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO properties (key, value, created_at) VALUES (?, ?, ?)", key, query, now)
	if err != nil {
		return err
	}

	return tx.Commit()
}
