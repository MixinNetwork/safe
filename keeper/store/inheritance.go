package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
)

type InheritanceLock struct {
	LockId    string
	RequestId string
	Hash      string
	Holder    string
	Address   string
	Chain     byte
	Duration  time.Duration
	State     byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

var inheritanceLockCols = []string{"lock_id", "request_id", "hash", "holder", "address", "chain", "duration", "state", "created_at", "updated_at"}

func (s *SQLite3Store) processInheritanceLockOperation(ctx context.Context, tx *sql.Tx, lock *InheritanceLock) error {
	existed, err := s.checkExistence(ctx, tx, "SELECT lock_id FROM inheritance_locks WHERE lock_id=?", lock.LockId)
	if err != nil || existed {
		return err
	}

	vals := []any{lock.LockId, lock.RequestId, lock.Hash, lock.Holder, lock.Address, lock.Chain, lock.Duration, lock.State, lock.CreatedAt, lock.UpdatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("inheritance_locks", inheritanceLockCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT inheritance_locks %v", err)
	}
	return nil
}

func (s *SQLite3Store) ReadInheritanceLock(ctx context.Context, id string) (*InheritanceLock, error) {
	query := fmt.Sprintf("SELECT %s FROM inheritance_locks WHERE lock_id=?", strings.Join(inheritanceLockCols, ","))
	return s.readInheritanceLockByQuery(ctx, query, id)
}

func (s *SQLite3Store) ReadInheritanceLockByRequestId(ctx context.Context, id string) (*InheritanceLock, error) {
	query := fmt.Sprintf("SELECT %s FROM inheritance_locks WHERE request_id=?", strings.Join(inheritanceLockCols, ","))
	return s.readInheritanceLockByQuery(ctx, query, id)
}

func (s *SQLite3Store) ReadLatestInheritanceLockByHolder(ctx context.Context, holder string) (*InheritanceLock, error) {
	query := fmt.Sprintf("SELECT %s FROM inheritance_locks WHERE holder=? ORDER BY created_at DESC LIMIT 1", strings.Join(inheritanceLockCols, ","))
	return s.readInheritanceLockByQuery(ctx, query, holder)
}

func (s *SQLite3Store) readInheritanceLockByQuery(ctx context.Context, query string, params ...any) (*InheritanceLock, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer common.Rollback(tx)

	row := tx.QueryRowContext(ctx, query, params...)

	var lock InheritanceLock
	err = row.Scan(&lock.LockId, &lock.RequestId, &lock.Hash, &lock.Holder, &lock.Address, &lock.Chain, &lock.Duration, &lock.State, &lock.CreatedAt, &lock.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &lock, nil
}

func (s *SQLite3Store) ListInheritanceLocksByHolder(ctx context.Context, holder string) ([]*InheritanceLock, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer common.Rollback(tx)

	query := fmt.Sprintf("SELECT %s FROM inheritance_locks WHERE holder=?", strings.Join(inheritanceLockCols, ","))
	rows, err := s.db.QueryContext(ctx, query, holder)
	if err != nil {
		return nil, err
	}
	defer common.CloseOrPanic(rows)

	var ls []*InheritanceLock
	for rows.Next() {
		var lock InheritanceLock
		err = rows.Scan(&lock.LockId, &lock.RequestId, &lock.Hash, &lock.Holder, &lock.Address, &lock.Chain, &lock.Duration, &lock.State, &lock.CreatedAt, &lock.UpdatedAt)
		if err != nil {
			return nil, err
		}
		ls = append(ls, &lock)
	}
	return ls, nil
}
