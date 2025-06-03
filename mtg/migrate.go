package mtg

import (
	"context"
	"time"
)

func MigrateSchema(ctx context.Context, s *SQLite3Store) error {
	txn, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(txn)

	key := "SCHEMA:VERSION:DEPOSIT:HASH:INDEX"
	exist, err := s.checkExistence(ctx, txn, "SELECT value FROM properties WHERE key=?", key)
	if err != nil || exist {
		return err
	}

	alter := "ALTER TABLE outputs ADD COLUMN deposit_hash VARCHAR;\n"
	alter += "ALTER TABLE outputs ADD COLUMN deposit_index INTEGER;\n"
	_, err = txn.ExecContext(ctx, alter)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	cols := []string{"key", "value", "created_at", "updated_at"}
	err = s.execOne(ctx, txn, buildInsertionSQL("properties", cols), key, alter, now, now)
	if err != nil {
		return err
	}
	return txn.Commit()
}
