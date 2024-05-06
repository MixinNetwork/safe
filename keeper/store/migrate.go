package store

import (
	"context"
	"database/sql"
	"time"
)

// FIXME remove this
func (s *SQLite3Store) Migrate(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	key, val := "SCHEMA:VERSION:migration", ""
	row := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&val)
	if err == nil || err != sql.ErrNoRows {
		return err
	}

	query := "ALTER TABLE requests ADD COLUMN sequence INTEGER;\n"
	query = query + "ALTER TABLE safes ADD COLUMN receiver VARCHAR;\n"
	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "UPDATE requests SET sequence=0")
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE safes SET receiver=?", "")
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
