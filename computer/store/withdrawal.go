package store

import (
	"context"
	"database/sql"
	"fmt"
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
