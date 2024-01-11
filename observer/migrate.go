package observer

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

	key, val := "SCHEMA:VERSION:664f750de4e357782227616ac6c6b5b050df2bbf", ""
	row := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&val)
	if err == nil || err != sql.ErrNoRows {
		return err
	}

	query := "ALTER TABLE deposits ADD COLUMN asset_address VARCHAR;"
	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE deposits SET asset_address=?", "")
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, "INSERT INTO properties (key, value, created_at) VALUES (?, ?, ?)", key, query, now)
	if err != nil {
		return err
	}

	return tx.Commit()
}
