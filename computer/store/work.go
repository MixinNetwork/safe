package store

import (
	"context"
	"fmt"
	"time"

	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/common"
)

func (s *SQLite3Store) WriteSessionWorkIfNotExist(ctx context.Context, sessionId, signerId string, round int, extra []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "SELECT created_at FROM session_works WHERE session_id=? AND signer_id=? AND round=?"
	existed, err := s.checkExistence(ctx, tx, query, sessionId, signerId, round)
	if err != nil || existed {
		return err
	}

	cols := []string{"session_id", "signer_id", "round", "extra", "created_at"}
	err = s.execOne(ctx, tx, buildInsertionSQL("session_works", cols),
		sessionId, signerId, round, common.Base91Encode(extra), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("SQLite3Store INSERT session_works %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) CountDailyWorks(ctx context.Context, members []party.ID, begin, end time.Time) ([]int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer common.Rollback(tx)

	works := make([]int, len(members))
	for i, id := range members {
		var work int
		sql := "SELECT COUNT(*) FROM session_works WHERE signer_id=? AND created_at>? AND created_at<?"
		row := tx.QueryRowContext(ctx, sql, id, begin, end)
		err = row.Scan(&work)
		if err != nil {
			return nil, err
		}
		works[i] = work
	}

	return works, nil
}
