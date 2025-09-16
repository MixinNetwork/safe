package store

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/mtg"
)

type SafeBalance struct {
	Address      string
	AssetId      string
	AssetAddress string
	SafeAssetId  string
	balance      string
	LatestTxHash string
	UpdatedAt    time.Time
}

func (sb *SafeBalance) UpdateBalance(change *big.Int) {
	balance := new(big.Int).Add(sb.BigBalance(), change)
	if balance.Sign() < 0 {
		panic(change.String())
	}
	sb.balance = balance.String()
}

func (sb *SafeBalance) BigBalance() *big.Int {
	b, ok := new(big.Int).SetString(sb.balance, 10)
	if !ok || b.Sign() < 0 {
		panic(sb.balance)
	}
	return b
}

func (s *SQLite3Store) CreateEthereumBalanceDepositFromRequest(ctx context.Context, safe *Safe, sb *SafeBalance, txHash string, index int64, amount *big.Int, sender string, req *common.Request, txs []*mtg.Transaction) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.createOrUpdateEthereumBalance(ctx, tx, sb)
	if err != nil {
		return err
	}

	vals := []any{txHash, index, sb.AssetId, amount.String(), sb.Address, sender, common.RequestStateDone, safe.Chain, safe.Holder, common.ActionObserverHolderDeposit, req.CreatedAt, req.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("deposits", depositsCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT deposits %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?", common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	err = s.writeActionResult(ctx, tx, req.Output.OutputId, "", txs, req.Id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite3Store) createOrUpdateEthereumBalance(ctx context.Context, tx *sql.Tx, sb *SafeBalance) error {
	existed, err := s.checkExistence(ctx, tx, "SELECT balance FROM ethereum_balances WHERE address=? AND asset_id=?", sb.Address, sb.AssetId)
	if err != nil {
		return err
	} else if !existed {
		cols := []string{"address", "asset_id", "asset_address", "safe_asset_id", "balance", "latest_tx_hash", "updated_at"}
		vals := []any{sb.Address, sb.AssetId, sb.AssetAddress, sb.SafeAssetId, sb.balance, "", time.Now().UTC()}
		err = s.execOne(ctx, tx, buildInsertionSQL("ethereum_balances", cols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT ethereum_balances %v", err)
		}
	} else {
		err = s.execOne(ctx, tx, "UPDATE ethereum_balances SET balance=?, updated_at=? WHERE address=? AND asset_id=? AND safe_asset_id=?",
			sb.balance, time.Now().UTC(), sb.Address, sb.AssetId, sb.SafeAssetId)
		if err != nil {
			return fmt.Errorf("UPDATE ethereum_balances %v", err)
		}
	}

	return nil
}

func (s *SQLite3Store) ReadEthereumBalance(ctx context.Context, address, assetId, safeAssetId string) (*SafeBalance, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer common.Rollback(tx)

	query := "SELECT address,asset_id,asset_address,safe_asset_id,balance,latest_tx_hash,updated_at FROM ethereum_balances WHERE address=? AND asset_id=?"
	row := tx.QueryRowContext(ctx, query, address, assetId)

	var sb SafeBalance
	err = row.Scan(&sb.Address, &sb.AssetId, &sb.AssetAddress, &sb.SafeAssetId, &sb.balance, &sb.LatestTxHash, &sb.UpdatedAt)
	if err == sql.ErrNoRows {
		return &SafeBalance{
			Address:      address,
			AssetId:      assetId,
			SafeAssetId:  safeAssetId,
			balance:      "0",
			LatestTxHash: "",
			UpdatedAt:    time.Now().UTC(),
		}, nil
	} else if err != nil {
		return nil, err
	}
	if sb.SafeAssetId != safeAssetId {
		panic(sb.AssetId)
	}
	return &sb, nil
}

func (s *SQLite3Store) ReadAllEthereumTokenBalances(ctx context.Context, address string) ([]*SafeBalance, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer common.Rollback(tx)

	query := "SELECT address,asset_id,asset_address,safe_asset_id,balance,latest_tx_hash,updated_at FROM ethereum_balances WHERE address=?"
	rows, err := s.db.QueryContext(ctx, query, address)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sbs []*SafeBalance
	for rows.Next() {
		var b SafeBalance
		err = rows.Scan(&b.Address, &b.AssetId, &b.AssetAddress, &b.SafeAssetId, &b.balance, &b.LatestTxHash, &b.UpdatedAt)
		if err != nil {
			return nil, err
		}
		if b.SafeAssetId == "" {
			panic(b.AssetId)
		}
		sbs = append(sbs, &b)
	}
	return sbs, nil
}

func (s *SQLite3Store) ReadAllEthereumTokenBalancesMap(ctx context.Context, address string) (map[string]*SafeBalance, error) {
	sbs, err := s.ReadAllEthereumTokenBalances(ctx, address)
	if err != nil {
		return nil, err
	}
	sbm := make(map[string]*SafeBalance, len(sbs))
	for _, sb := range sbs {
		sbm[sb.AssetAddress] = sb
	}
	return sbm, nil
}

func (s *SQLite3Store) ReadPositiveEthereumTokenBalancesMap(ctx context.Context, address string) (map[string]*SafeBalance, error) {
	sbs, err := s.ReadAllEthereumTokenBalances(ctx, address)
	if err != nil {
		return nil, err
	}
	sbm := make(map[string]*SafeBalance, len(sbs))
	for _, sb := range sbs {
		if sb.BigBalance().Sign() == 0 {
			continue
		}
		sbm[sb.AssetAddress] = sb
	}
	return sbm, nil
}
