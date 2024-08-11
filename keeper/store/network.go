package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/shopspring/decimal"
)

type Asset struct {
	AssetId   string
	MixinId   string
	AssetKey  string
	Symbol    string
	Name      string
	Decimals  uint32
	Chain     byte
	CreatedAt time.Time
}

type NetworkInfo struct {
	RequestId string
	Chain     byte
	Fee       uint64
	Height    uint64
	Hash      string
	CreatedAt time.Time
}

type OperationParams struct {
	RequestId            string
	Chain                byte
	OperationPriceAsset  string
	OperationPriceAmount decimal.Decimal
	TransactionMinimum   decimal.Decimal
	CreatedAt            time.Time
}

var assetCols = []string{"asset_id", "mixin_id", "asset_key", "symbol", "name", "decimals", "chain", "created_at"}
var infoCols = []string{"request_id", "chain", "fee", "height", "hash", "created_at"}
var paramsCols = []string{"request_id", "chain", "price_asset", "price_amount", "transaction_minimum", "created_at"}

func (s *SQLite3Store) ReadNetworkInfo(ctx context.Context, id string) (*NetworkInfo, error) {
	query := fmt.Sprintf("SELECT %s FROM network_infos WHERE request_id=?", strings.Join(infoCols, ","))
	row := s.db.QueryRowContext(ctx, query, id)

	var n NetworkInfo
	err := row.Scan(&n.RequestId, &n.Chain, &n.Fee, &n.Height, &n.Hash, &n.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &n, err
}

func (s *SQLite3Store) ReadLatestNetworkInfo(ctx context.Context, chain byte, offset time.Time) (*NetworkInfo, error) {
	query := fmt.Sprintf("SELECT %s FROM network_infos WHERE chain=? AND created_at<=? ORDER BY created_at DESC, request_id DESC LIMIT 1", strings.Join(infoCols, ","))
	row := s.db.QueryRowContext(ctx, query, chain, offset)

	var n NetworkInfo
	err := row.Scan(&n.RequestId, &n.Chain, &n.Fee, &n.Height, &n.Hash, &n.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &n, err
}

func (s *SQLite3Store) WriteNetworkInfoFromRequest(ctx context.Context, info *NetworkInfo, req *common.Request) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	vals := []any{info.RequestId, info.Chain, info.Fee, info.Height, info.Hash, info.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("network_infos", infoCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT network_infos %v", err)
	}
	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), info.RequestId)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	err = s.writeActionResult(ctx, tx, req.Output.OutputId, "", nil, info.RequestId)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadLatestOperationParams(ctx context.Context, chain byte, offset time.Time) (*OperationParams, error) {
	query := fmt.Sprintf("SELECT %s FROM operation_params WHERE chain=? AND created_at<=? ORDER BY created_at DESC, request_id DESC LIMIT 1", strings.Join(paramsCols, ","))
	row := s.db.QueryRowContext(ctx, query, chain, offset)

	var p OperationParams
	var price, minimum string
	err := row.Scan(&p.RequestId, &p.Chain, &p.OperationPriceAsset, &price, &minimum, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	p.OperationPriceAmount = decimal.RequireFromString(price)
	p.TransactionMinimum = decimal.RequireFromString(minimum)
	return &p, nil
}

func (s *SQLite3Store) WriteOperationParamsFromRequest(ctx context.Context, params *OperationParams, req *common.Request) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existed, err := s.checkExistence(ctx, tx, "SELECT request_id FROM requests WHERE request_id=? AND state=?", params.RequestId, common.RequestStateDone)
	if err != nil || existed {
		return err
	}

	amount := params.OperationPriceAmount.String()
	minimum := params.TransactionMinimum.String()
	vals := []any{params.RequestId, params.Chain, params.OperationPriceAsset, amount, minimum, params.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("operation_params", paramsCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT operation_params %v", err)
	}
	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), params.RequestId)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	err = s.writeActionResult(ctx, tx, req.Output.OutputId, "", nil, params.RequestId)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite3Store) ReadAssetMeta(ctx context.Context, id string) (*Asset, error) {
	query := fmt.Sprintf("SELECT %s FROM assets WHERE asset_id=? OR mixin_id=?", strings.Join(assetCols, ","))
	row := s.db.QueryRowContext(ctx, query, id, id)

	var a Asset
	err := row.Scan(&a.AssetId, &a.MixinId, &a.AssetKey, &a.Symbol, &a.Name, &a.Decimals, &a.Chain, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *SQLite3Store) WriteAssetMeta(ctx context.Context, asset *Asset) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	vals := []any{asset.AssetId, asset.MixinId, asset.AssetKey, asset.Symbol, asset.Name, asset.Decimals, asset.Chain, asset.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("assets", assetCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT assets %v", err)
	}
	return tx.Commit()
}
