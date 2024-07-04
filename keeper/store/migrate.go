package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/MixinNetwork/safe/common"
)

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
		_, err = tx.ExecContext(ctx, query)
		if err != nil {
			return err
		}
	}

	for _, asset := range ms {
		chainAssetId := common.SafeChainAssetId(asset.Chain)
		if asset.AssetId == chainAssetId {
			_, err = tx.ExecContext(ctx, "UPDATE safes SET safe_asset_id=? where address=?", asset.SafeAssetId, asset.Address)
			if err != nil {
				return err
			}
		}
		switch asset.Chain {
		case common.SafeChainEthereum, common.SafeChainMVM, common.SafeChainPolygon:
			_, err = tx.ExecContext(ctx, "UPDATE ethereum_balances SET safe_asset_id=? where address=? AND asset_id=?", asset.SafeAssetId, asset.Address, asset.AssetId)
			if err != nil {
				return err
			}
		default:
			panic(asset.Chain)
		}
	}
	err = s.createMigrateAssets(ctx, tx, ms)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "UPDATE requests SET sequence=0")
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
