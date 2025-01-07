package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/MixinNetwork/safe/common"
)

var confirmedWithdrawalCols = []string{"hash", "trace_id", "call_id", "created_at"}

func (s *SQLite3Store) writeConfirmedWithdrawal(ctx context.Context, tx *sql.Tx, req *Request, hash, traceId, callId string) error {
	vals := []any{hash, traceId, callId, req.CreatedAt}
	err := s.execOne(ctx, tx, buildInsertionSQL("confirmed_withdrawals", confirmedWithdrawalCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT confirmed_withdrawals %v", err)
	}
	return nil
}

func (s *SQLite3Store) IsConfirmedWithdrawal(ctx context.Context, hash string) (bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT trace_id FROM confirmed_withdrawals WHERE hash=?", hash)
	return existed, err
}
