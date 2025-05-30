package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/safe/common"
)

type UserOutput struct {
	OutputId        string
	UserId          string
	TransactionHash string
	OutputIndex     int
	AssetId         string
	ChainId         string
	Amount          string
	State           byte
	SignedBy        sql.NullString
	CreatedAt       time.Time
	UpdatedAt       time.Time

	Asset bot.AssetNetwork
}

var userOutputCols = []string{"output_id", "user_id", "transaction_hash", "output_index", "asset_id", "chain_id", "amount", "state", "signed_by", "created_at", "updated_at"}

func userOutputFromRow(row Row) (*UserOutput, error) {
	var output UserOutput
	err := row.Scan(&output.OutputId, &output.UserId, &output.TransactionHash, &output.OutputIndex, &output.AssetId, &output.ChainId, &output.Amount, &output.State, &output.SignedBy, &output.CreatedAt, &output.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &output, err
}

func (s *SQLite3Store) WriteUserDepositWithRequest(ctx context.Context, req *Request, output *UserOutput) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	vals := []any{output.OutputId, output.UserId, output.TransactionHash, output.OutputIndex, output.AssetId, output.ChainId, output.Amount, output.State, output.SignedBy, output.CreatedAt, output.UpdatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("user_outputs", userOutputCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT user_outputs %v", err)
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ListUserOutputsByHashAndState(ctx context.Context, user_id, hash string, state byte) ([]*UserOutput, error) {
	vals := []any{user_id, hash}
	query := fmt.Sprintf("SELECT %s FROM user_outputs WHERE user_id=? AND transaction_hash=?", strings.Join(userOutputCols, ","))
	if state > 0 {
		query += " AND state=?"
		vals = append(vals, state)
	}
	query += " ORDER BY created_at ASC LIMIT 100"
	return s.listUserOutputsByQuery(ctx, query, vals...)
}

func (s *SQLite3Store) listUserOutputsByQuery(ctx context.Context, query string, params ...any) ([]*UserOutput, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	rows, err := s.db.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var outputs []*UserOutput
	for rows.Next() {
		output, err := userOutputFromRow(rows)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, output)
	}
	return outputs, nil
}
