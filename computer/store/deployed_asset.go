package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	solana "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
)

var deployedAssetCols = []string{"asset_id", "chain_id", "address", "decimals", "state", "created_at"}

func deployedAssetFromRow(row Row) (*solana.DeployedAsset, error) {
	var a solana.DeployedAsset
	err := row.Scan(&a.AssetId, &a.ChainId, &a.Address, &a.Decimals, &a.State, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *SQLite3Store) ReadDeployedAsset(ctx context.Context, id string, state int64) (*solana.DeployedAsset, error) {
	query := fmt.Sprintf("SELECT %s FROM deployed_assets WHERE asset_id=?", strings.Join(deployedAssetCols, ","))
	values := []any{id}
	if state > 0 {
		query = query + " AND state=?"
		values = append(values, state)
	}
	row := s.db.QueryRowContext(ctx, query, values...)

	return deployedAssetFromRow(row)
}

func (s *SQLite3Store) ReadDeployedAssetByAddress(ctx context.Context, address string) (*solana.DeployedAsset, error) {
	query := fmt.Sprintf("SELECT %s FROM deployed_assets WHERE address=? AND state=?", strings.Join(deployedAssetCols, ","))
	row := s.db.QueryRowContext(ctx, query, address, common.RequestStateDone)

	return deployedAssetFromRow(row)
}

func (s *SQLite3Store) ListDeployedAssets(ctx context.Context) ([]*solana.DeployedAsset, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	query := fmt.Sprintf("SELECT %s FROM deployed_assets WHERE state=? LIMIT 500", strings.Join(deployedAssetCols, ","))
	rows, err := s.db.QueryContext(ctx, query, common.RequestStateDone)
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
