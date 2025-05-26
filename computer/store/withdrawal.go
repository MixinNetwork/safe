package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
)

type ConfirmedWithdrawal struct {
	Hash      string
	TraceId   string
	CallId    string
	CreatedAt time.Time
}

var confirmedWithdrawalCols = []string{"hash", "trace_id", "call_id", "created_at"}

func (s *SQLite3Store) WriteConfirmedWithdrawal(ctx context.Context, w *ConfirmedWithdrawal) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	vals := []any{w.Hash, w.TraceId, w.CallId, w.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("confirmed_withdrawals", confirmedWithdrawalCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT confirmed_withdrawals %v", err)
	}

	err = s.writeProperty(ctx, tx, WithdrawalConfirmRequestTimeKey, w.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) CheckUnconfirmedWithdrawals(ctx context.Context, call *SystemCall) (bool, error) {
	if !call.WithdrawalTraces.Valid {
		panic(call.RequestId)
	}
	ids := call.GetWithdrawalIds()
	if len(ids) == 0 {
		return false, nil
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	placeholders := strings.Repeat("?, ", len(ids))
	placeholders = strings.TrimSuffix(placeholders, ", ")

	args := make([]any, len(ids))
	for i, addr := range ids {
		args[i] = addr
	}

	query := fmt.Sprintf("SELECT COUNT(1) FROM confirmed_withdrawals WHERE trace_id IN (%s)", placeholders)
	row := s.db.QueryRowContext(ctx, query, args...)

	var count int
	err := row.Scan(&count)
	if err == sql.ErrNoRows {
		return true, nil
	} else if err != nil {
		return true, err
	}
	return count == len(ids), err
}
