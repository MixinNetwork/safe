package store

import (
	"context"

	"github.com/MixinNetwork/safe/common"
)

func (s *SQLite3Store) CheckMigrateAsset(ctx context.Context, address, asset_id string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer common.Rollback(tx)

	return s.checkExistence(ctx, tx, "SELECT safe_asset_id FROM migrate_assets WHERE address=? AND asset_id=?", address, asset_id)
}
