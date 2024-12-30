package store

import (
	"context"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/common"
)

func (s *SQLite3Store) WriteWithdrawalFeeIfNotExists(ctx context.Context, txId, feeId string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT fee_trace_id FROM withdrawal_fees WHERE trace_id=?", txId)
	if err != nil || existed {
		return err
	}

	cols := []string{"trace_id", "fee_trace_id", "created_at"}
	values := []any{txId, feeId, time.Now().UTC()}
	err = s.execOne(ctx, tx, buildInsertionSQL("withdrawal_fees", cols), values...)
	if err != nil {
		return fmt.Errorf("SQLite3Store INSERT withdrawal_fees %v", err)
	}

	return tx.Commit()
}
