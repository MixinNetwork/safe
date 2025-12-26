package store

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

	query1 := "UPDATE transactions SET state=? WHERE transaction_hash=? AND state=?;"
	err = s.execOne(ctx, tx, query1, common.RequestStateDone, "6a5ccb71871db47550acd5429764d724c0e26e9ef63e214954edce2ee80a7e90", common.RequestStateFailed)
	if err != nil {
		return err
	}

	query2 := "UPDATE safes SET nonce=? WHERE holder=? AND nonce=? AND state=?;"
	err = s.execOne(ctx, tx, query2, 181, "02cf89b2507b8b3ceac013f675da6cf68f1ac7a3c74de2621d9d4790d67bde43a5", 180, common.RequestStateDone)
	if err != nil {
		return err
	}

	query3 := "UPDATE ethereum_balances SET balance=? WHERE address=? AND asset_id=? AND safe_asset_id=? AND balance=?;"
	err = s.execOne(ctx, tx, query3, "74500000000000000000000", "0xA82bCC5b1942c3BF74C8eef18E1a6E0d8FAFA4cb", "c94ac88f-4671-3976-b60a-09064f1811e8", "b5a91ff6-a78b-3838-9fa5-225636c093d0", "77000000000000000000000")
	if err != nil {
		return err
	}

	query := query1 + query2 + query3
	_, err = tx.ExecContext(ctx, "INSERT INTO properties (key, value, created_at) VALUES (?, ?, ?)", key, query, now)
	if err != nil {
		return err
	}

	return tx.Commit()
}
