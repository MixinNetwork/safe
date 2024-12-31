package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/common"
)

type Session struct {
	Id         string
	RequestId  string
	MixinHash  string
	MixinIndex int
	Index      int
	Operation  byte
	Public     string
	Extra      string
	State      byte
	CreatedAt  time.Time
	PreparedAt sql.NullTime
}

func (r *Session) AsOperation() *common.Operation {
	extra, err := hex.DecodeString(r.Extra)
	if err != nil {
		panic(err)
	}

	return &common.Operation{
		Id:     r.Id,
		Type:   r.Operation,
		Public: r.Public,
		Extra:  extra,
	}
}

func (s *SQLite3Store) ReadSession(ctx context.Context, sessionId string) (*Session, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var r Session
	query := "SELECT session_id, request_id, mixin_hash, mixin_index, operation, public, extra, state, created_at, prepared_at FROM sessions WHERE session_id=?"
	row := s.db.QueryRowContext(ctx, query, sessionId)
	err := row.Scan(&r.Id, &r.RequestId, &r.MixinHash, &r.MixinIndex, &r.Operation, &r.Public, &r.Extra, &r.State, &r.CreatedAt, &r.PreparedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &r, err
}

func (s *SQLite3Store) WriteSessionsWithRequest(ctx context.Context, req *Request, sessions []*Session, needsCommittment bool) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	for _, session := range sessions {
		existed, err := s.checkExistence(ctx, tx, "SELECT session_id FROM sessions WHERE session_id=?", session.Id)
		if err != nil || existed {
			return err
		}

		cols := []string{"session_id", "request_id", "mixin_hash", "mixin_index", "sub_index", "operation", "public",
			"extra", "state", "created_at", "updated_at"}
		vals := []any{session.Id, session.RequestId, session.MixinHash, session.MixinIndex, session.Index, session.Operation, session.Public,
			session.Extra, common.RequestStateInitial, session.CreatedAt, session.CreatedAt}
		if !needsCommittment {
			cols = append(cols, "committed_at", "prepared_at")
			vals = append(vals, session.CreatedAt, session.CreatedAt)
		}
		err = s.execOne(ctx, tx, buildInsertionSQL("sessions", cols), vals...)
		if err != nil {
			return fmt.Errorf("SQLite3Store INSERT sessions %v", err)
		}
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?", common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}
	err = s.writeActionResult(ctx, tx, req.Output.OutputId, "", nil, req.Id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) FailSession(ctx context.Context, sessionId string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	// the pending state is important, because we needs to let the other nodes know our failed
	// result, and the pending state allows the node to process this session accordingly
	err = s.execOne(ctx, tx, "UPDATE sessions SET state=?, updated_at=? WHERE session_id=? AND state=?",
		common.RequestStatePending, time.Now().UTC(), sessionId, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE sessions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) MarkSessionPending(ctx context.Context, sessionId string, fingerprint string, extra []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.execOne(ctx, tx, "UPDATE sessions SET extra=?, state=?, updated_at=? WHERE session_id=? AND public=? AND state=? AND prepared_at IS NOT NULL",
		hex.EncodeToString(extra), common.RequestStatePending, time.Now().UTC(), sessionId, fingerprint, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE sessions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) MarkSessionCommitted(ctx context.Context, sessionId string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	committedAt := time.Now().UTC()
	query := "UPDATE sessions SET committed_at=?, updated_at=? WHERE session_id=? AND state=? AND committed_at IS NULL"
	err = s.execOne(ctx, tx, query, committedAt, committedAt, sessionId, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE sessions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) MarkSessionDone(ctx context.Context, sessionId string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.execOne(ctx, tx, "UPDATE sessions SET state=?, updated_at=? WHERE session_id=? AND state=?",
		common.RequestStateDone, time.Now().UTC(), sessionId, common.RequestStatePending)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE sessions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ListInitialSessions(ctx context.Context, limit int) ([]*Session, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	cols := "session_id, request_id, mixin_hash, mixin_index, operation, public, extra, state, created_at"
	sql := fmt.Sprintf("SELECT %s FROM sessions WHERE state=? AND committed_at IS NULL AND prepared_at IS NULL ORDER BY operation DESC, created_at ASC, session_id ASC LIMIT %d", cols, limit)
	return s.listSessionsByQuery(ctx, sql, common.RequestStateInitial)
}

func (s *SQLite3Store) ListPreparedSessions(ctx context.Context, limit int) ([]*Session, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	cols := "session_id, request_id, mixin_hash, mixin_index, operation, public, extra, state, created_at"
	sql := fmt.Sprintf("SELECT %s FROM sessions WHERE state=? AND committed_at IS NOT NULL AND prepared_at IS NOT NULL ORDER BY operation DESC, created_at ASC, session_id ASC LIMIT %d", cols, limit)
	return s.listSessionsByQuery(ctx, sql, common.RequestStateInitial)
}

func (s *SQLite3Store) ListPendingSessions(ctx context.Context, limit int) ([]*Session, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	cols := "session_id, request_id, mixin_hash, mixin_index, operation, public, extra, state, created_at"
	sql := fmt.Sprintf("SELECT %s FROM sessions WHERE state=? ORDER BY created_at ASC, session_id ASC LIMIT %d", cols, limit)
	return s.listSessionsByQuery(ctx, sql, common.RequestStatePending)
}

func (s *SQLite3Store) listSessionsByQuery(ctx context.Context, sql string, state int) ([]*Session, error) {
	rows, err := s.db.QueryContext(ctx, sql, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		var r Session
		err := rows.Scan(&r.Id, &r.RequestId, &r.MixinHash, &r.MixinIndex, &r.Operation, &r.Public, &r.Extra, &r.State, &r.CreatedAt)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, &r)
	}
	return sessions, nil
}
