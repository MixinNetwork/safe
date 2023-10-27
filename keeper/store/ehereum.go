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

func (s *SQLite3Store) UpdateEthereumBalanceFromRequest(ctx context.Context, safe *Safe, txHash string, index int64, amount *big.Int, req *common.Request, assetId, sender string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existed, err := s.checkExistence(ctx, tx, "SELECT balance FROM ethereum_balances WHERE address=? AND asset_id=?", safe.Address, assetId)
	if err != nil {
		return err
	} else if !existed {
		cols := []string{"address", "asset_id", "balance", "latest_tx_hash", "updated_at"}
		vals := []any{safe.Address, assetId, amount.String(), txHash, time.Now().UTC()}
		err = s.execOne(ctx, tx, buildInsertionSQL("ethereum_balances", cols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT ethereum_balances %v", err)
		}
	} else {
		err = s.execOne(ctx, tx, "UPDATE ethereum_balances SET balance=?, latest_tx_hash=?, updated_at=? WHERE address=? AND asset_id=?", amount.String(), txHash, time.Now().UTC(), safe.Address, assetId)
		if err != nil {
			return fmt.Errorf("UPDATE ethereum_balances %v", err)
		}
	}

	vals := []any{txHash, index, assetId, amount.String(), safe.Address, sender, common.RequestStateDone, safe.Chain, safe.Holder, common.ActionObserverHolderDeposit, req.Id, req.CreatedAt, req.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("deposits", depositsCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT deposits %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?", common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) CreateOrUpdateEthereumBalanceWithCloseBalance(ctx context.Context, safe *Safe, balance *big.Int, assetId string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existed, err := s.checkExistence(ctx, tx, "SELECT balance FROM ethereum_balances WHERE address=? AND asset_id=?", safe.Address, assetId)
	if err != nil {
		return err
	} else if !existed {
		cols := []string{"address", "asset_id", "balance", "latest_tx_hash", "updated_at"}
		vals := []any{safe.Address, assetId, balance.String(), "", time.Now().UTC()}
		err = s.execOne(ctx, tx, buildInsertionSQL("ethereum_balances", cols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT ethereum_balances %v", err)
		}
	} else {
		err = s.execOne(ctx, tx, "UPDATE ethereum_balances SET balance=?, updated_at=? WHERE address=? AND asset_id=?", balance.String(), time.Now().UTC(), safe.Address, assetId)
		if err != nil {
			return fmt.Errorf("UPDATE ethereum_balances %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadEthereumBalance(ctx context.Context, address, assetId string) (*SafeBalance, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	query := "SELECT address,asset_id,balance,latest_tx_hash,updated_at FROM ethereum_balances WHERE address=? AND asset_id=?"
	row := tx.QueryRowContext(ctx, query, address, assetId)

	var sb SafeBalance
	var bStr string
	err = row.Scan(&sb.Address, &sb.AssetId, &bStr, &sb.LatestTxHash, &sb.UpdatedAt)
	if err == sql.ErrNoRows {
		return &SafeBalance{
			Address:      address,
			AssetId:      assetId,
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
	sb.Balance = balance
	return &sb, nil
}
