package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
)

var unmigratedSafeCols = []string{"holder", "chain", "signer", "observer", "timelock", "path", "address", "extra", "receivers", "threshold", "request_id", "nonce", "state", "created_at", "updated_at"}

func (s *SQLite3Store) ListUnmigratedSafesWithState(ctx context.Context) ([]*Safe, error) {
	query := fmt.Sprintf("SELECT %s FROM safes ORDER BY created_at ASC, request_id ASC", strings.Join(unmigratedSafeCols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var safes []*Safe
	for rows.Next() {
		var s Safe
		var receivers string
		err := rows.Scan(&s.Holder, &s.Chain, &s.Signer, &s.Observer, &s.Timelock, &s.Path, &s.Address, &s.Extra, &receivers, &s.Threshold, &s.RequestId, &s.Nonce, &s.State, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			return nil, err
		}
		s.Receivers = strings.Split(receivers, ";")
		safes = append(safes, &s)
	}
	return safes, nil
}

// FIXME remove this
func (s *SQLite3Store) Migrate(ctx context.Context, ms []*MigrateAsset) error {
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

	query := ""
	if !common.CheckTestEnvironment(ctx) {
		query = "ALTER TABLE requests ADD COLUMN sequence INTEGER;\n"
		query = query + "ALTER TABLE safes ADD COLUMN safe_asset_id VARCHAR;\n"
		query = query + "ALTER TABLE ethereum_balances ADD COLUMN safe_asset_id VARCHAR;\n"
		query = query + "CREATE UNIQUE INDEX IF NOT EXISTS safes_by_safe_asset_id ON safes(safe_asset_id) WHERE safe_asset_id IS NOT NULL;\n"
		_, err = tx.ExecContext(ctx, query)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, "UPDATE requests SET sequence=0")
	if err != nil {
		return err
	}

	for _, asset := range ms {
		if asset.AssetId == common.SafeChainAssetId(asset.Chain) {
			err = s.execOne(ctx, tx, "UPDATE safes SET safe_asset_id=? where address=? and safe_asset_id IS NULL",
				asset.SafeAssetId, asset.Address)
			if err != nil {
				return err
			}
		} else {
			err = s.execOne(ctx, tx, "UPDATE ethereum_balances SET safe_asset_id=? where address=? AND asset_id=? AND safe_asset_id IS NULL",
				asset.SafeAssetId, asset.Address, asset.AssetId)
			if err != nil {
				return err
			}
		}
	}
	err = s.createMigrateAssets(ctx, tx, ms)
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
