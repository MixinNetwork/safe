package store

import (
	"context"
	"database/sql"
	"encoding/json"
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

type AccountPlan struct {
	AccountPriceAsset  string
	AccountPriceAmount decimal.Decimal
	TransactionMinimum decimal.Decimal
}

var assetCols = []string{"asset_id", "mixin_id", "asset_key", "symbol", "name", "decimals", "chain", "created_at"}
var infoCols = []string{"request_id", "chain", "fee", "height", "hash", "created_at"}

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

func (s *SQLite3Store) ReadLatestNetworkInfo(ctx context.Context, chain byte) (*NetworkInfo, error) {
	query := fmt.Sprintf("SELECT %s FROM network_infos WHERE chain=? ORDER BY created_at DESC LIMIT 1", strings.Join(infoCols, ","))
	row := s.db.QueryRowContext(ctx, query, chain)

	var n NetworkInfo
	err := row.Scan(&n.RequestId, &n.Chain, &n.Fee, &n.Height, &n.Hash, &n.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &n, err
}

func (s *SQLite3Store) WriteNetworkInfoFromRequest(ctx context.Context, info *NetworkInfo) error {
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
	return tx.Commit()
}

func accountPricePropertyKey(chain byte) string {
	return fmt.Sprintf("safe-account-price-%d", chain)
}

func (s *SQLite3Store) ReadAccountPlan(ctx context.Context, chain byte) (*AccountPlan, error) {
	key := accountPricePropertyKey(chain)
	value, err := s.ReadProperty(ctx, key)
	if err != nil || value == "" {
		return nil, err
	}

	var plan AccountPlan
	err = json.Unmarshal([]byte(value), &plan)
	return &plan, err
}

func (s *SQLite3Store) WriteAccountPlanFromRequest(ctx context.Context, chain byte, assetId string, amount, minimum decimal.Decimal, req *common.Request) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	key := accountPricePropertyKey(chain)
	value, err := json.Marshal(AccountPlan{
		AccountPriceAsset:  assetId,
		AccountPriceAmount: amount,
		TransactionMinimum: minimum,
	})
	if err != nil {
		panic(err)
	}
	existed, err := s.checkExistence(ctx, tx, "SELECT value FROM properties WHERE key=?", key)
	if err != nil {
		return err
	}

	if existed {
		err = s.execOne(ctx, tx, "UPDATE properties SET value=?, created_at=? WHERE key=?", value, req.CreatedAt, key)
		if err != nil {
			return fmt.Errorf("UPDATE properties %v", err)
		}
	} else {
		cols := []string{"key", "value", "created_at"}
		err = s.execOne(ctx, tx, buildInsertionSQL("properties", cols), key, value, req.CreatedAt)
		if err != nil {
			return fmt.Errorf("INSERT properties %v", err)
		}
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
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
