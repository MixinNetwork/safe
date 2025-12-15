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

	key, val := "SCHEMA:VERSION:STUCK_TX", ""
	row := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&val)
	if err == nil || err != sql.ErrNoRows {
		return err
	}
	now := time.Now().UTC()

	query1 := "ALTER TABLE transactions ADD COLUMN stuck BOOLEAN;\n"
	err = s.execOne(ctx, tx, query1)
	if err != nil {
		return err
	}

	query2 := "UPDATE transactions SET state=?, spent_hash=?, updated_at=? WHERE transaction_hash=?;\n"
	err = s.execOne(ctx, tx, query2,
		common.RequestStateDone, "0x4a58ca86cf5731b1d505c96757546b564a7c88f33539f7d9b23c6dce6f53b343", now, "6a5ccb71871db47550acd5429764d724c0e26e9ef63e214954edce2ee80a7e90")
	if err != nil {
		return err
	}

	query := query1 + query2
	_, err = tx.ExecContext(ctx, "INSERT INTO properties (key, value, created_at, updated_at) VALUES (?, ?, ?, ?)", key, query, now, now)
	if err != nil {
		return err
	}

	return tx.Commit()
}
