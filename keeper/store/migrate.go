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

	key, val := "SCHEMA:VERSION:664f750de4e357782227616ac6c6b5b050df2bbf", ""
	row := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&val)
	if err == nil || err != sql.ErrNoRows {
		return err
	}

	query := "ALTER TABLE safes ADD COLUMN nonce INTEGER;\n"
	query = query + "ALTER TABLE transactions ADD COLUMN asset_id VARCHAR;\n"
	query = query + "CREATE TABLE IF NOT EXISTS ethereum_balances (address VARCHAR NOT NULL, asset_id VARCHAR NOT NULL, asset_address VARCHAR NOT NULL, balance VARCHAR NOT NULL, latest_tx_hash VARCHAR NOT NULL, updated_at TIMESTAMP NOT NULL, PRIMARY KEY ('address', 'asset_id'));\n"
	query = query + "CREATE TABLE IF NOT EXISTS deposits (transaction_hash VARCHAR NOT NULL, output_index VARCHAR NOT NULL, asset_id VARCHAR NOT NULL, amount VARCHAR NOT NULL, receiver VARCHAR NOT NULL, sender VARCHAR NOT NULL, state INTEGER NOT NULL, chain INTEGER NOT NULL, holder VARCHAR NOT NULL, category INTEGER NOT NULL, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, PRIMARY KEY ('transaction_hash', 'output_index'));\n"
	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "UPDATE safes SET nonce=0")
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE transactions SET asset_id=''")
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
