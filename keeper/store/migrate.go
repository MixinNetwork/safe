package store

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
)

var unmigratedSafeCols = []string{"holder", "chain", "signer", "observer", "timelock", "path", "address", "extra", "receivers", "threshold", "request_id", "nonce", "state", "created_at", "updated_at"}

func (s *SQLite3Store) ListUnmigratedSafesWithState(ctx context.Context, state int) ([]*Safe, error) {
	query := fmt.Sprintf("SELECT %s FROM safes WHERE state=? ORDER BY created_at ASC, request_id ASC", strings.Join(unmigratedSafeCols, ","))
	rows, err := s.db.QueryContext(ctx, query, state)
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
		var bStr string
		err = rows.Scan(&b.Address, &b.AssetId, &b.AssetAddress, &bStr, &b.LatestTxHash, &b.UpdatedAt)
		if err != nil {
			return nil, err
		}
		balance, _ := new(big.Int).SetString(bStr, 10)
		b.Balance = balance
		sbs = append(sbs, &b)
	}
	return sbs, nil
}

// FIXME remove this
func (s *SQLite3Store) Migrate(ctx context.Context, ms []*MigrateAsset) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	key, val := "SCHEMA:VERSION:migration", ""
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
	_, err = tx.ExecContext(ctx, "UPDATE requests SET sequence=0")
	if err != nil {
		return err
	}

	for _, asset := range ms {
		chainAssetId := common.SafeChainAssetId(asset.Chain)
		if asset.AssetId == chainAssetId {
			_, err = tx.ExecContext(ctx, "UPDATE safes SET safe_asset_id=? where address=?", asset.SafeAssetId, asset.Address)
			if err != nil {
				return err
			}
		}
		switch asset.Chain {
		case common.SafeChainEthereum, common.SafeChainMVM, common.SafeChainPolygon:
			_, err = tx.ExecContext(ctx, "UPDATE ethereum_balances SET safe_asset_id=? where address=? AND asset_id=?", asset.SafeAssetId, asset.Address, asset.AssetId)
			if err != nil {
				return err
			}
		}
	}
	err = s.createMigrateAssets(ctx, tx, ms)
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
