package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
)

type FeeInfo struct {
	Id        string
	Ratio     string
	CreatedAt time.Time
}

var feeCols = []string{"fee_id", "ratio", "created_at"}

func feeFromRow(row Row) (*FeeInfo, error) {
	var f FeeInfo
	err := row.Scan(&f.Id, &f.Ratio, &f.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &f, err
}

func (s *SQLite3Store) WriteFeeInfoWithRequest(ctx context.Context, req *Request, ratio string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT fee_id FROM fees WHERE fee_id=?", req.Id)
	if err != nil || existed {
		return err
	}

	vals := []any{req.Id, ratio, req.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("fees", feeCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT fees %v", err)
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadFeeInfoById(ctx context.Context, id string) (*FeeInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := fmt.Sprintf("SELECT %s FROM fees where fee_id=?", strings.Join(feeCols, ","))
	row := s.db.QueryRowContext(ctx, query, id)

	return feeFromRow(row)
}

func (s *SQLite3Store) ReadLatestFeeInfo(ctx context.Context) (*FeeInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := fmt.Sprintf("SELECT %s FROM fees ORDER BY created_at DESC LIMIT 1", strings.Join(feeCols, ","))
	row := s.db.QueryRowContext(ctx, query)

	return feeFromRow(row)
}
