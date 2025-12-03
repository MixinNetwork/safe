package observer

import (
	"context"
	"database/sql"
	"time"

	"github.com/MixinNetwork/safe/common"
)

func (s *SQLite3Store) Migrate(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	key, val := "SCHEMA:VERSION:INHERITANCE", ""
	row := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&val)
	if err == nil || err != sql.ErrNoRows {
		return err
	}

	query := "ALTER TABLE recoveries ADD COLUMN inheritance BOOLEAN DEFAULT false;\n"
	_, err = tx.ExecContext(ctx, query, false)
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
