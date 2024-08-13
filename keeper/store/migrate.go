package store

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
)

var unmigratedSafeCols = []string{"holder", "chain", "signer", "observer", "timelock", "path", "address", "extra", "receivers", "threshold", "request_id", "nonce", "state", "created_at", "updated_at"}

func (s *SQLite3Store) ListUnmigratedSafesWithState(ctx context.Context) ([]*Safe, error) {
	query := fmt.Sprintf("SELECT %s FROM safes ORDER BY created_at ASC, request_id ASC", strings.Join(unmigratedSafeCols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var safes []*Safe
	for rows.Next() {
		var s Safe
		var receivers string
		err := rows.Scan(&s.Holder, &s.Chain, &s.Signer, &s.Observer, &s.Timelock, &s.Path, &s.Address, &s.Extra, &receivers, &s.Threshold, &s.RequestId, &s.Nonce, &s.State, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			return nil, err
		}
		s.Receivers = strings.Split(receivers, ";")
		safes = append(safes, &s)
	}
	return safes, nil
}

func (s *SQLite3Store) ReadUnmigratedEthereumAllBalance(ctx context.Context, address string) ([]*SafeBalance, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	query := "SELECT address,asset_id,asset_address,balance,latest_tx_hash,updated_at FROM ethereum_balances WHERE address=?"
	rows, err := s.db.QueryContext(ctx, query, address)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sbs []*SafeBalance
	for rows.Next() {
		var b SafeBalance
		err = rows.Scan(&b.Address, &b.AssetId, &b.AssetAddress, &b.balance, &b.LatestTxHash, &b.UpdatedAt)
		if err != nil {
			return nil, err
		}
		sbs = append(sbs, &b)
	}
	return sbs, nil
}

func (s *SQLite3Store) ReadUnmigratedLatestRequest(ctx context.Context) (*common.Request, error) {
	var requestCols = []string{"request_id", "mixin_hash", "mixin_index", "asset_id", "amount", "role", "action", "curve", "holder", "extra", "state", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM requests ORDER BY created_at DESC, request_id DESC LIMIT 1", strings.Join(requestCols, ","))
	row := s.db.QueryRowContext(ctx, query)

	return unmigratedRequestFromRow(row)
}

func unmigratedRequestFromRow(row *sql.Row) (*common.Request, error) {
	var mh string
	var r common.Request
	err := row.Scan(&r.Id, &mh, &r.MixinIndex, &r.AssetId, &r.Amount, &r.Role, &r.Action, &r.Curve, &r.Holder, &r.ExtraHEX, &r.State, &r.CreatedAt, &time.Time{})
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	r.MixinHash, err = crypto.HashFromString(mh)
	return &r, err
}

func (s *SQLite3Store) CheckFullyMigrated(ctx context.Context) bool {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		panic(err)
	}
	defer tx.Rollback()

	key, val := "SCHEMA:VERSION:4fca1938ab13afa2f58bc3fabb4c653331b13476", ""
	row := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&val)
	if err == sql.ErrNoRows {
		return false
	}
	if err != nil {
		panic(err)
	}
	return true
}

// FIXME remove this
func (s *SQLite3Store) MigrateDepositCreated(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	key, val := "SCHEMA:VERSION:eb16681a8dd60e586d43a361384f0035fcac068b", ""
	row := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&val)
	if err == nil || err != sql.ErrNoRows {
		return err
	}

	query := "UPDATE deposits SET created_at=updated_at"
	err = s.execMultiple(ctx, tx, 227, query)
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

// FIXME remove this
func (s *SQLite3Store) Migrate(ctx context.Context, ss, es []*MigrateAsset) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	key, val := "SCHEMA:VERSION:4fca1938ab13afa2f58bc3fabb4c653331b13476", ""
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
		query = query + "CREATE UNIQUE INDEX IF NOT EXISTS safes_by_safe_asset_id ON safes(safe_asset_id) WHERE safe_asset_id IS NOT NULL;\n"
		_, err = tx.ExecContext(ctx, query)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, "UPDATE requests SET sequence=0 WHERE sequence IS NULL")
	if err != nil {
		return err
	}

	for _, asset := range ss {
		logger.Printf("store.Migrate() => %#v", asset)
		sql := "UPDATE safes SET safe_asset_id=? where address=? and safe_asset_id IS NULL"
		err = s.execOne(ctx, tx, sql, asset.SafeAssetId, asset.Address)
		if err != nil {
			return err
		}
	}

	for _, asset := range es {
		logger.Printf("store.Migrate() => %#v", asset)
		switch asset.Chain {
		case common.SafeChainBitcoin:
		case common.SafeChainLitecoin:
		default:
			sql := "UPDATE ethereum_balances SET safe_asset_id=? where address=? AND asset_id=? AND safe_asset_id IS NULL"
			err = s.execOne(ctx, tx, sql, asset.SafeAssetId, asset.Address, asset.AssetId)
			if err != nil {
				return err
			}
		}
	}

	for _, a := range es {
		if !slices.ContainsFunc(ss, func(e *MigrateAsset) bool {
			return e.Address == a.Address && e.AssetId == a.AssetId && e.Chain == a.Chain
		}) {
			ss = append(ss, a)
		}
	}
	err = s.createMigrateAssets(ctx, tx, ss)
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
