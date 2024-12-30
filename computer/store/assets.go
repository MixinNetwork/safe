package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/gagliardetto/solana-go"
)

type DeployedAsset struct {
	AssetId   string
	Address   string
	CreatedAt time.Time

	PrivateKey *solana.PrivateKey
}

func (a *DeployedAsset) PublicKey() solana.PublicKey {
	return solana.MustPublicKeyFromBase58(a.Address)
}

func DeployedAssetsFromTransferTokens(transfers []solanaApp.TokenTransfers) []*DeployedAsset {
	var as []*DeployedAsset
	for _, t := range transfers {
		if t.SolanaAsset {
			continue
		}
		as = append(as, &DeployedAsset{
			AssetId: t.AssetId,
			Address: t.Mint.String(),
		})
	}
	return as
}

var deployedAssetCols = []string{"asset_id", "address", "created_at"}

func deployedAssetFromRow(row *sql.Row) (*DeployedAsset, error) {
	var a DeployedAsset
	err := row.Scan(&a.AssetId, &a.Address, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &a, err
}

func (s *SQLite3Store) writeDeployedAssetsIfNorExist(ctx context.Context, tx *sql.Tx, req *Request, assets []*DeployedAsset) error {
	for _, asset := range assets {
		existed, err := s.checkExistence(ctx, tx, "SELECT address FROM deployed_assets WHERE asset_id=?", asset.AssetId)
		if err != nil {
			return err
		}
		if existed {
			continue
		}

		vals := []any{asset.AssetId, asset.Address, req.CreatedAt}
		err = s.execOne(ctx, tx, buildInsertionSQL("deployed_assets", deployedAssetCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT deployed_assets %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) ReadDeployedAsset(ctx context.Context, id string) (*DeployedAsset, error) {
	query := fmt.Sprintf("SELECT %s FROM deployed_assets WHERE asset_id=?", strings.Join(deployedAssetCols, ","))
	row := s.db.QueryRowContext(ctx, query, id)

	return deployedAssetFromRow(row)
}
