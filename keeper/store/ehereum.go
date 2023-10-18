package store

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"time"

	"github.com/MixinNetwork/safe/common"
)

type SafeBalance struct {
	Address      string
	AssetId      string
	Balance      *big.Int
	LatestTxHash string
	UpdatedAt    time.Time
}

func (s *SQLite3Store) UpdateEthereumBalanceFromRequest(ctx context.Context, receiver, asset_id, txHash string, amount *big.Int, req *common.Request, chain byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var balance *big.Int
	row := tx.QueryRowContext(ctx, "SELECT balance FROM ethereum_balances WHERE address=? AND asset_id=?", receiver, asset_id)
	err = row.Scan(&balance)
	if err == sql.ErrNoRows {
		cols := []string{"address", "asset_id", "balance", "latest_tx_hash", "updated_at"}
		vals := []any{receiver, asset_id, amount.String(), txHash, time.Now().UTC()}
		err = s.execOne(ctx, tx, buildInsertionSQL("ethereum_balances", cols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT ethereum_balances %v", err)
		}
	} else {
		err = s.execOne(ctx, tx, "UPDATE ethereum_balances SET balance=?, latest_tx_hash, updated_at=? WHERE address=?", amount.String(), txHash, time.Now().UTC(), receiver)
		if err != nil {
			return fmt.Errorf("UPDATE ethereum_balances %v", err)
		}
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?", common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) ReadEthereumBalance(ctx context.Context, address, asset_id string) (*SafeBalance, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	query := "SELECT address,asset_id,balance,latest_tx_hash,updated_at FROM ethereum_balances WHERE address=? AND asset_id=?"
	row := tx.QueryRowContext(ctx, query, address, asset_id)

	var safeBalance SafeBalance
	var bStr string
	err = row.Scan(&safeBalance.Address, &safeBalance.AssetId, &bStr, &safeBalance.LatestTxHash, &safeBalance.UpdatedAt)
	if err == sql.ErrNoRows {
		return &SafeBalance{
			Address:      address,
			AssetId:      asset_id,
			Balance:      big.NewInt(0),
			LatestTxHash: "",
			UpdatedAt:    time.Now().UTC(),
		}, nil
	} else if err != nil {
		return nil, err
	}
	balance, ok := new(big.Int).SetString(bStr, 10)
	if !ok {
		return nil, fmt.Errorf("Fail to parse value to big.Int")
	}
	safeBalance.Balance = balance
	return &safeBalance, nil
}
