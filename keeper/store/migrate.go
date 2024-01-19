package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/MixinNetwork/safe/apps/bitcoin"
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
	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "UPDATE safes SET nonce=0")
	if err != nil {
		return err
	}

	for _, c := range []byte{bitcoin.ChainBitcoin, bitcoin.ChainLitecoin} {
		assetId := "c6d0c728-2624-429b-8e0d-d9d19b6592fa"
		if c == bitcoin.ChainLitecoin {
			assetId = "76c802a2-7c88-447f-a93e-c29c9e5dd9c8"
		}
		_, err = tx.ExecContext(ctx, "UPDATE transactions SET asset_id=? WHERE chain=?", assetId, c)
		if err != nil {
			return err
		}
	}

	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, "INSERT INTO properties (key, value, created_at) VALUES (?, ?, ?)", key, query, now)
	if err != nil {
		return err
	}

	return tx.Commit()
}
