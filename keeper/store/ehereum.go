package store

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"time"

	"github.com/MixinNetwork/safe/common"
)

func (s *SQLite3Store) UpdateEthereumBalanceFromRequest(ctx context.Context, receiver, asset_id string, amount *big.Int, req *common.Request, chain byte) error {
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
		cols := []string{"address", "asset_id", "balance", "updated_at"}
		vals := []any{receiver, asset_id, amount.Uint64(), time.Now().UTC()}
		err = s.execOne(ctx, tx, buildInsertionSQL("ethereum_balances", cols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT ethereum_balances %v", err)
		}
	} else {
		err = s.execOne(ctx, tx, "UPDATE ethereum_balances SET balance=?, updated_at=? WHERE address=?", amount.Uint64(), time.Now().UTC(), receiver)
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

func (s *SQLite3Store) ReadEthereumBalance(ctx context.Context, address, asset_id string) (*big.Int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	query := "SELECT balance FROM ethereum_balances WHERE address=? AND asset_id=?"
	row := tx.QueryRowContext(ctx, query, address, asset_id)

	var balance uint64
	err = row.Scan(&balance)
	if err == sql.ErrNoRows {
		return big.NewInt(0), nil
	} else if err != nil {
		return nil, err
	}
	return new(big.Int).SetUint64(balance), nil
}
