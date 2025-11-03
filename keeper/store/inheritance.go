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
	if err != nil {
		return err
	}
	if !existed {
		vals := []any{lock.LockId, lock.RequestId, lock.Hash, lock.Holder, lock.Address, lock.Chain, lock.Duration, lock.State, lock.CreatedAt, lock.UpdatedAt}
		err := s.execOne(ctx, tx, buildInsertionSQL("inheritance_locks", inheritanceLockCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT inheritance_locks %v", err)
		}
	}

	err = s.execOne(ctx, tx, "UPDATE inheritance_locks SET request_hash=?, hash=?, duration=?, state=?, updated_at=? WHERE lock_id=?",
		lock.RequestId, lock.Hash, lock.Duration, lock.State, lock.UpdatedAt, lock.LockId)
	if err != nil {
		return fmt.Errorf("UPDATE inheritance_locks %v", err)
	}
	return nil
}

func (s *SQLite3Store) ReadInheritanceLock(ctx context.Context, id string) (*InheritanceLock, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer common.Rollback(tx)

	return s.readInheritanceLock(ctx, tx, id)
}

func (s *SQLite3Store) ReadInheritanceLockByRequestId(ctx context.Context, id string) (*InheritanceLock, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer common.Rollback(tx)

	query := fmt.Sprintf("SELECT %s FROM inheritance_locks WHERE request_id=?", strings.Join(inheritanceLockCols, ","))
	row := tx.QueryRowContext(ctx, query, id)

	var lock InheritanceLock
	err = row.Scan(&lock.LockId, &lock.RequestId, &lock.Hash, &lock.Holder, &lock.Address, &lock.Chain, &lock.Duration, &lock.State, &lock.CreatedAt, &lock.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &lock, nil
}

func (s *SQLite3Store) readInheritanceLock(ctx context.Context, tx *sql.Tx, id string) (*InheritanceLock, error) {
	query := fmt.Sprintf("SELECT %s FROM inheritance_locks WHERE lock_id=?", strings.Join(inheritanceLockCols, ","))
	row := tx.QueryRowContext(ctx, query, id)

	var lock InheritanceLock
	err := row.Scan(&lock.LockId, &lock.RequestId, &lock.Hash, &lock.Holder, &lock.Address, &lock.Chain, &lock.Duration, &lock.State, &lock.CreatedAt, &lock.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &lock, nil
}

func (s *SQLite3Store) readInitialInheritanceLockByRequestHash(ctx context.Context, tx *sql.Tx, hash string) (*InheritanceLock, error) {
	query := fmt.Sprintf("SELECT %s FROM inheritance_locks WHERE request_hash=? AND state=?", strings.Join(inheritanceLockCols, ","))
	row := tx.QueryRowContext(ctx, query, hash, common.RequestStateInitial)

	var lock InheritanceLock
	err := row.Scan(&lock.LockId, &lock.RequestId, &lock.Hash, &lock.Holder, &lock.Address, &lock.Chain, &lock.Duration, &lock.State, &lock.CreatedAt, &lock.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &lock, nil
}

func (s *SQLite3Store) ListUnfailedInheritanceLocksByHolder(ctx context.Context, holder string) ([]*InheritanceLock, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer common.Rollback(tx)

	query := fmt.Sprintf("SELECT %s FROM inheritance_locks WHERE holder=? AND state!=?", strings.Join(inheritanceLockCols, ","))
	rows, err := s.db.QueryContext(ctx, query, holder, common.RequestStateFailed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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
