package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/common"
)

type UserOutput struct {
	OutputId        string
	UserId          string
	RequestId       string
	TransactionHash string
	OutputIndex     int
	AssetId         string
	ChainId         string
	Amount          string
	State           byte
	Sequence        uint64
	SignedBy        sql.NullString
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (s *SQLite3Store) WriteUserDepositWithRequest(ctx context.Context, req *Request, output *UserOutput) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	cols := []string{"output_id", "user_id", "request_id", "transaction_hash", "output_index", "asset_id", "chain_id", "amount", "state", "sequence", "signed_by", "created_at", "updated_at"}
	vals := []any{output.OutputId, output.UserId, output.RequestId, output.TransactionHash, output.OutputIndex, output.AssetId, output.ChainId, output.Amount, output.State, output.Sequence, output.SignedBy, output.CreatedAt, output.UpdatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("user_outputs", cols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT user_outputs %v", err)
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}
