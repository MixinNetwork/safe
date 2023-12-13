package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type Deposit struct {
	TransactionHash string
	OutputIndex     int64
	AssetId         string
	Amount          string
	Receiver        string
	Sender          string
	State           int
	Chain           byte
	Holder          string
	Category        byte
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

var depositsCols = []string{"transaction_hash", "output_index", "asset_id", "amount", "receiver", "sender", "state", "chain", "holder", "category", "created_at", "updated_at"}

func (s *SQLite3Store) ReadDeposit(ctx context.Context, hash string, index int64) (*Deposit, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	query := fmt.Sprintf("SELECT %s FROM deposits WHERE transaction_hash=? AND output_index=?", strings.Join(depositsCols, ","))
	row := tx.QueryRowContext(ctx, query, hash, index)

	var d Deposit
	err = row.Scan(&d.TransactionHash, &d.OutputIndex, &d.AssetId, &d.Amount, &d.Receiver, &d.Sender, &d.State, &d.Chain, &d.Holder, &d.Category, &d.CreatedAt, &d.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &d, err
}
