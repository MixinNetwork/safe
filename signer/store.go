package signer

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
)

//go:embed schema.sql
var SCHEMA string

type SQLite3Store struct {
	db    *sql.DB
	mutex *sync.Mutex
}

func OpenSQLite3Store(path string) (*SQLite3Store, error) {
	db, err := common.OpenSQLite3Store(path, SCHEMA)
	if err != nil {
		return nil, err
	}
	return &SQLite3Store{
		db:    db,
		mutex: new(sync.Mutex),
	}, nil
}

func (s *SQLite3Store) Close() error {
	return s.db.Close()
}

func (s *SQLite3Store) WriteKeyIfNotExists(ctx context.Context, sessionId string, curve uint8, public string, conf []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existed, err := s.checkExistence(ctx, tx, "SELECT curve FROM keys WHERE public=?", public)
	if err != nil || existed {
		return err
	}

	timestamp := time.Now().UTC()
	err = s.execOne(ctx, tx, "INSERT INTO keys (public, fingerprint, curve, share, session_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		public, hex.EncodeToString(common.Fingerprint(public)), curve, hex.EncodeToString(conf), sessionId, timestamp)
	if err != nil {
		return fmt.Errorf("SQLite3Store INSERT keys %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE sessions SET public=?, state=?, updated_at=? WHERE session_id=? AND created_at=updated_at AND state=?",
		public, common.RequestStatePending, timestamp, sessionId, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE sessions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadKeyByFingerprint(ctx context.Context, sum string) (string, uint8, []byte, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var curve uint8
	var public, share string
	row := s.db.QueryRowContext(ctx, "SELECT public, curve, share FROM keys WHERE fingerprint=?", sum)
	err := row.Scan(&public, &curve, &share)
	if err == sql.ErrNoRows {
		return "", 0, nil, nil
	} else if err != nil {
		return "", 0, nil, err
	}
	conf := common.DecodeHexOrPanic(share)
	return public, curve, conf, err
}

func (s *SQLite3Store) ReadSession(ctx context.Context, sessionId string) (*Session, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var r Session
	row := s.db.QueryRowContext(ctx, "SELECT session_id, mixin_hash, mixin_index, operation, curve, public, extra, state, created_at FROM sessions WHERE session_id=?", sessionId)
	err := row.Scan(&r.Id, &r.MixinHash, &r.MixinIndex, &r.Operation, &r.Curve, &r.Public, &r.Extra, &r.State, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &r, err
}

func (s *SQLite3Store) WriteSessionSignerIfNotExist(ctx context.Context, sessionId, signerId string, extra []byte, createdAt time.Time, self bool) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existed, err := s.checkExistence(ctx, tx, "SELECT extra FROM session_signers WHERE session_id=? AND signer_id=?", sessionId, signerId)
	if err != nil || existed {
		return err
	}

	err = s.execOne(ctx, tx, "INSERT INTO session_signers (session_id, signer_id, extra, created_at) VALUES (?, ?, ?, ?)",
		sessionId, signerId, hex.EncodeToString(extra), createdAt)
	if err != nil {
		return fmt.Errorf("SQLite3Store INSERT session_signers %v", err)
	}

	existed, err = s.checkExistence(ctx, tx, "SELECT session_id FROM sessions WHERE session_id=? AND state=?", sessionId, common.RequestStateInitial)
	if err != nil {
		return err
	}
	if self && existed {
		err = s.execOne(ctx, tx, "UPDATE sessions SET state=?, updated_at=? WHERE session_id=? AND state=?",
			common.RequestStatePending, createdAt, sessionId, common.RequestStateInitial)
		if err != nil {
			return fmt.Errorf("SQLite3Store UPDATE sessions %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) ListSessionSigners(ctx context.Context, sessionId string) (map[string]string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	rows, err := s.db.QueryContext(ctx, "SELECT signer_id, extra FROM session_signers WHERE session_id=?", sessionId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var signer, extra string
	signers := make(map[string]string)
	for rows.Next() {
		err := rows.Scan(&signer, &extra)
		if err != nil {
			return nil, err
		}
		signers[signer] = extra
	}
	return signers, nil
}

func (s *SQLite3Store) WriteSessionIfNotExist(ctx context.Context, op *common.Operation, transaction crypto.Hash, outputIndex int, createdAt time.Time) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existed, err := s.checkExistence(ctx, tx, "SELECT session_id FROM sessions WHERE session_id=?", op.Id)
	if err != nil || existed {
		return err
	}

	err = s.execOne(ctx, tx, "INSERT INTO sessions (session_id, mixin_hash, mixin_index, operation, curve, public, extra, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		op.Id, transaction.String(), outputIndex, op.Type, op.Curve, op.Public, hex.EncodeToString(op.Extra), common.RequestStateInitial, createdAt, createdAt)
	if err != nil {
		return fmt.Errorf("SQLite3Store INSERT sessions %v", err)
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
	defer tx.Rollback()

	err = s.execOne(ctx, tx, "UPDATE sessions SET state=?, updated_at=? WHERE session_id=? AND created_at=updated_at AND state=?",
		common.RequestStatePending, time.Now().UTC(), sessionId, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE sessions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) FinishSignSession(ctx context.Context, sessionId string, curve uint8, fingerprint string, extra []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.execOne(ctx, tx, "UPDATE sessions SET extra=?, state=?, updated_at=? WHERE session_id=? AND curve=? AND public=? AND created_at=updated_at AND state=?",
		hex.EncodeToString(extra), common.RequestStatePending, time.Now().UTC(), sessionId, curve, fingerprint, common.RequestStateInitial)
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
	defer tx.Rollback()

	err = s.execOne(ctx, tx, "UPDATE sessions SET state=?, updated_at=? WHERE session_id=? AND state=?",
		common.RequestStateDone, time.Now().UTC(), sessionId, common.RequestStatePending)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE sessions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ListInitialSessions(ctx context.Context, limit int) ([]*common.Operation, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sql := fmt.Sprintf("SELECT session_id, operation, curve, public, extra FROM sessions WHERE state=? ORDER BY operation DESC, created_at ASC LIMIT %d", limit)
	return s.listSessionsByQuery(ctx, sql, common.RequestStateInitial)
}

func (s *SQLite3Store) ListPendingSessions(ctx context.Context, limit int) ([]*common.Operation, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sql := fmt.Sprintf("SELECT session_id, operation, curve, public, extra FROM sessions WHERE state=? ORDER BY created_at ASC LIMIT %d", limit)
	return s.listSessionsByQuery(ctx, sql, common.RequestStatePending)
}

func (s *SQLite3Store) listSessionsByQuery(ctx context.Context, sql string, state int) ([]*common.Operation, error) {
	rows, err := s.db.QueryContext(ctx, sql, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var operations []*common.Operation
	for rows.Next() {
		var r Session
		err := rows.Scan(&r.Id, &r.Operation, &r.Curve, &r.Public, &r.Extra)
		if err != nil {
			return nil, err
		}
		operations = append(operations, &common.Operation{
			Id:     r.Id,
			Type:   r.Operation,
			Curve:  r.Curve,
			Public: r.Public,
			Extra:  common.DecodeHexOrPanic(r.Extra),
		})
	}
	return operations, nil
}

type State struct {
	Initial int
	Pending int
	Done    int
	Keys    int
}

func (s *SQLite3Store) SessionsState(ctx context.Context) (*State, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var state State
	row := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE state=?", common.RequestStateInitial)
	err = row.Scan(&state.Initial)
	if err != nil {
		return nil, err
	}

	row = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE state=?", common.RequestStatePending)
	err = row.Scan(&state.Pending)
	if err != nil {
		return nil, err
	}

	row = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE state=?", common.RequestStateDone)
	err = row.Scan(&state.Done)
	if err != nil {
		return nil, err
	}

	row = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM keys")
	err = row.Scan(&state.Keys)
	if err != nil {
		return nil, err
	}

	return &state, nil
}

func (s *SQLite3Store) execOne(ctx context.Context, tx *sql.Tx, sql string, params ...any) error {
	res, err := tx.ExecContext(ctx, sql, params...)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return fmt.Errorf("SQLite3Store.execOne(%s) => %d %v", sql, rows, err)
	}
	return nil
}

func (s *SQLite3Store) checkExistence(ctx context.Context, tx *sql.Tx, sql string, params ...any) (bool, error) {
	rows, err := tx.QueryContext(ctx, sql, params...)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	return rows.Next(), nil
}

func (s *SQLite3Store) ReadProperty(ctx context.Context, k string) (string, error) {
	row := s.db.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", k)
	err := row.Scan(&k)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return k, err
}

func (s *SQLite3Store) WriteProperty(ctx context.Context, k, v string) error {
	logger.Printf("SQLite3Store.WriteProperty(%s)", k)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var ov string
	row := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", k)
	err = row.Scan(&ov)
	if err == sql.ErrNoRows {
	} else if err != nil {
		return fmt.Errorf("SQLite3Store INSERT properties %v", err)
	} else if ov != v {
		return fmt.Errorf("SQLite3Store INSERT properties %s", k)
	} else {
		return nil
	}

	err = s.execOne(ctx, tx, "INSERT INTO properties (key, value, created_at) VALUES (?, ?, ?)", k, v, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("SQLite3Store INSERT properties %v", err)
	}
	return tx.Commit()
}
