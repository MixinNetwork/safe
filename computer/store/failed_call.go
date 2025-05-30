package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/common"
)

func (s *SQLite3Store) WriteFailedCallIfNotExist(ctx context.Context, call *SystemCall, reason string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT reason FROM failed_calls WHERE call_id=?", call.RequestId)
	if err != nil || existed {
		return err
	}

	vals := []any{call.RequestId, reason, time.Now()}
	err = s.execOne(ctx, tx, buildInsertionSQL("failed_calls", []string{"call_id", "reason", "created_at"}), vals...)
	if err != nil {
		return fmt.Errorf("INSERT failed_calls %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadFailReason(ctx context.Context, id string) (string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	row := s.db.QueryRowContext(ctx, "SELECT reason FROM failed_calls WHERE call_id=?", id)
	var reason string
	err := row.Scan(&reason)
	if err == sql.ErrNoRows {
		return "", nil
	} else if err != nil {
		return "", err
	}
	return reason, nil
}
