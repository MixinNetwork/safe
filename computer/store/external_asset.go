package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
)

type ExternalAsset struct {
	AssetId     string
	Uri         sql.NullString
	CreatedAt   time.Time
	RequestedAt sql.NullTime
}

var externalAssetCols = []string{"asset_id", "uri", "created_at", "requested_at"}

func externalAssetFromRow(row Row) (*ExternalAsset, error) {
	var a ExternalAsset
	err := row.Scan(&a.AssetId, &a.Uri, &a.CreatedAt, &a.RequestedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *SQLite3Store) WriteExternalAssets(ctx context.Context, assets []*ExternalAsset) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	for _, asset := range assets {
		vals := []any{asset.AssetId, nil, asset.CreatedAt, nil}
		err = s.execOne(ctx, tx, buildInsertionSQL("external_assets", externalAssetCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT external_assets %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) UpdateExternalAssetUri(ctx context.Context, id, uri string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE external_assets SET uri=? WHERE asset_id=? AND uri IS NULL"
	_, err = tx.ExecContext(ctx, query, uri, id)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE external_assets %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) MarkExternalAssetRequested(ctx context.Context, id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE external_assets SET requested_at=? WHERE asset_id=? AND requested_at IS NULL"
	_, err = tx.ExecContext(ctx, query, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE external_assets %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadExternalAsset(ctx context.Context, id string) (*ExternalAsset, error) {
	query := fmt.Sprintf("SELECT %s FROM external_assets WHERE asset_id=?", strings.Join(externalAssetCols, ","))
	row := s.db.QueryRowContext(ctx, query, id)

	return externalAssetFromRow(row)
}

func (s *SQLite3Store) ListUnrequestedAssets(ctx context.Context) ([]*ExternalAsset, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	query := fmt.Sprintf("SELECT %s FROM external_assets WHERE requested_at IS NULL LIMIT 500", strings.Join(externalAssetCols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var as []*ExternalAsset
	for rows.Next() {
		asset, err := externalAssetFromRow(rows)
		if err != nil {
			return nil, err
		}
		as = append(as, asset)
	}
	return as, nil
}

func (s *SQLite3Store) ListAssetUris(ctx context.Context) (map[string]string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	query := fmt.Sprintf("SELECT %s FROM external_assets WHERE uri IS NOT NULL AND requested_at IS NOT NULL LIMIT 500", strings.Join(externalAssetCols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	um := make(map[string]string)
	for rows.Next() {
		asset, err := externalAssetFromRow(rows)
		if err != nil {
			return nil, err
		}
		um[asset.AssetId] = asset.Uri.String
	}
	return um, nil
}
