package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/gofrs/uuid"
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

var assetCols = []string{"asset_id", "mixin_id", "asset_key", "symbol", "name", "decimals", "chain", "created_at"}
var infoCols = []string{"request_id", "chain", "fee", "height", "hash", "created_at"}

func (s *SQLite3Store) ReadNetworkInfo(ctx context.Context, chain byte) (*NetworkInfo, error) {
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

func (s *SQLite3Store) ReadAccountPrice(ctx context.Context, chain byte) (string, decimal.Decimal, error) {
	key := accountPricePropertyKey(chain)
	value, err := s.ReadProperty(ctx, key)
	if err != nil || value == "" {
		return "", decimal.Zero, err
	}

	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		panic(value)
	}
	amount, err := decimal.NewFromString(parts[1])
	if err != nil {
		panic(value)
	}
	assetId := uuid.Must(uuid.FromString(parts[0])).String()
	return assetId, amount, nil
}

func (s *SQLite3Store) WriteAccountPriceFromRequest(ctx context.Context, chain byte, assetId string, amount decimal.Decimal, req *common.Request) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	key := accountPricePropertyKey(chain)
	value := fmt.Sprintf("%s:%s", assetId, amount.String())
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
