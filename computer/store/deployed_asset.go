package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/MixinNetwork/safe/apps/solana"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
)

var deployedAssetCols = []string{"asset_id", "chain_id", "address", "decimals", "created_at"}

func deployedAssetFromRow(row Row) (*solana.DeployedAsset, error) {
	var a solana.DeployedAsset
	err := row.Scan(&a.AssetId, &a.ChainId, &a.Address, &a.Decimals, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *SQLite3Store) WriteDeployedAssetsWithRequest(ctx context.Context, req *Request, assets []*solanaApp.DeployedAsset) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	for _, asset := range assets {
		existed, err := s.checkExistence(ctx, tx, "SELECT address FROM deployed_assets WHERE asset_id=?", asset.AssetId)
		if err != nil {
			return err
		}
		if existed {
			continue
		}

		vals := []any{asset.AssetId, asset.ChainId, asset.Address, asset.Decimals, req.CreatedAt}
		err = s.execOne(ctx, tx, buildInsertionSQL("deployed_assets", deployedAssetCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT deployed_assets %v", err)
		}
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadDeployedAsset(ctx context.Context, id string) (*solana.DeployedAsset, error) {
	query := fmt.Sprintf("SELECT %s FROM deployed_assets WHERE asset_id=?", strings.Join(deployedAssetCols, ","))
	row := s.db.QueryRowContext(ctx, query, id)

	return deployedAssetFromRow(row)
}

func (s *SQLite3Store) ReadDeployedAssetByAddress(ctx context.Context, address string) (*solana.DeployedAsset, error) {
	query := fmt.Sprintf("SELECT %s FROM deployed_assets WHERE address=?", strings.Join(deployedAssetCols, ","))
	row := s.db.QueryRowContext(ctx, query, address)

	return deployedAssetFromRow(row)
}

func (s *SQLite3Store) ListDeployedAssets(ctx context.Context) ([]*solana.DeployedAsset, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := fmt.Sprintf("SELECT %s FROM deployed_assets LIMIT 500", strings.Join(deployedAssetCols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var as []*solana.DeployedAsset
	for rows.Next() {
		asset, err := deployedAssetFromRow(rows)
		if err != nil {
			return nil, err
		}
		as = append(as, asset)
	}
	return as, nil
}
