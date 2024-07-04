package store

import (
	"context"
	"database/sql"
	"fmt"
)

type MigrateAsset struct {
	SafeAssetId string
	Chain       byte
	Address     string
	AssetId     string
}

var migrateAssetCols = []string{"safe_asset_id", "chain", "address", "asset_id"}

func (s *SQLite3Store) createMigrateAssets(ctx context.Context, tx *sql.Tx, ms []*MigrateAsset) error {
	for _, ma := range ms {
		vals := []any{ma.SafeAssetId, ma.Chain, ma.Address, ma.AssetId}
		err := s.execOne(ctx, tx, buildInsertionSQL("migrate_assets", migrateAssetCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT migrate_assets %v", err)
		}
	}

	return nil
}

func (s *SQLite3Store) CheckMigrateAsset(ctx context.Context, address, asset_id string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	return s.checkExistence(ctx, tx, "SELECT safe_asset_id FROM migrate_assets WHERE address=? AND asset_id=?", address, asset_id)
}
