package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
)

//go:embed schema.sql
var SCHEMA string

type SQLite3Store struct {
	db    *sql.DB
	mutex *sync.Mutex
}

type SignResult struct {
	Signature []byte
	SSID      []byte
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

func (s *SQLite3Store) PrepareSessionSignerWithRequest(ctx context.Context, req *Request, sufficient bool, sessionId, signerId string, createdAt time.Time) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "SELECT extra FROM session_signers WHERE session_id=? AND signer_id=?"
	existed, err := s.checkExistence(ctx, tx, query, sessionId, signerId)
	if err != nil {
		return err
	}
	if !existed {
		cols := []string{"session_id", "signer_id", "extra", "created_at", "updated_at"}
		err = s.execOne(ctx, tx, buildInsertionSQL("session_signers", cols),
			sessionId, signerId, "", createdAt, createdAt)
		if err != nil {
			return fmt.Errorf("SQLite3Store INSERT session_signers %v", err)
		}
	}

	if sufficient {
		query := "SELECT prepared_at FROM sessions WHERE session_id=? AND prepared_at IS NOT NULL"
		existed, err := s.checkExistence(ctx, tx, query, sessionId)
		if err != nil {
			return err
		}

		if !existed {
			query = "UPDATE sessions SET prepared_at=?, updated_at=? WHERE session_id=? AND state=? AND prepared_at IS NULL"
			err = s.execOne(ctx, tx, query, createdAt, createdAt, sessionId, common.RequestStateInitial)
			if err != nil {
				return fmt.Errorf("SQLite3Store UPDATE sessions %v", err)
			}
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

func (s *SQLite3Store) WriteSessionSignerIfNotExist(ctx context.Context, sessionId, signerId string, extra []byte, createdAt time.Time, self bool) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT extra FROM session_signers WHERE session_id=? AND signer_id=?", sessionId, signerId)
	if err != nil || existed {
		return err
	}

	cols := []string{"session_id", "signer_id", "extra", "created_at", "updated_at"}
	err = s.execOne(ctx, tx, buildInsertionSQL("session_signers", cols),
		sessionId, signerId, hex.EncodeToString(extra), createdAt, createdAt)
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

func (s *SQLite3Store) UpdateSessionSigner(ctx context.Context, sessionId, signerId string, extra []byte, updatedAt time.Time, self bool) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "SELECT extra FROM session_signers WHERE session_id=? AND signer_id=?"
	existed, err := s.checkExistence(ctx, tx, query, sessionId, signerId)
	if err != nil || !existed {
		return err
	}

	query = "UPDATE session_signers SET extra=?, updated_at=? WHERE session_id=? AND signer_id=?"
	err = s.execOne(ctx, tx, query, hex.EncodeToString(extra), updatedAt, sessionId, signerId)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE session_signers %v", err)
	}

	existed, err = s.checkExistence(ctx, tx, "SELECT session_id FROM sessions WHERE session_id=? AND state=?", sessionId, common.RequestStateInitial)
	if err != nil {
		return err
	}
	if self && existed {
		err = s.execOne(ctx, tx, "UPDATE sessions SET state=?, updated_at=? WHERE session_id=? AND state=?",
			common.RequestStatePending, updatedAt, sessionId, common.RequestStateInitial)
		if err != nil {
			return fmt.Errorf("SQLite3Store UPDATE sessions %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) ListSessionPreparedMembers(ctx context.Context, sessionId string, threshold int) ([]party.ID, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	query := fmt.Sprintf("SELECT signer_id FROM session_signers WHERE session_id=? ORDER BY created_at ASC LIMIT %d", threshold)
	rows, err := s.db.QueryContext(ctx, query, sessionId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var signers []party.ID
	for rows.Next() {
		var signer string
		err := rows.Scan(&signer)
		if err != nil {
			return nil, err
		}
		signers = append(signers, party.ID(signer))
	}
	return signers, nil
}

func (s *SQLite3Store) ListSessionSignerResults(ctx context.Context, sessionId string) (map[string]string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	query := "SELECT signer_id, extra FROM session_signers WHERE session_id=?"
	rows, err := s.db.QueryContext(ctx, query, sessionId)
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

func (s *SQLite3Store) CheckActionResultsBySessionId(ctx context.Context, sessionId string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		panic(err)
	}
	defer common.Rollback(tx)

	query := "SELECT transactions,compaction FROM action_results where session_id=?"
	rows, err := tx.QueryContext(ctx, query, sessionId)
	if err != nil {
		panic(err)
	}
	var ts, compaction string
	for rows.Next() {
		err = rows.Scan(&ts, &compaction)
		if err == sql.ErrNoRows {
			continue
		} else if err != nil {
			panic(err)
		}

		tb, err := common.Base91Decode(ts)
		if err != nil {
			panic(ts)
		}
		txs, err := mtg.DeserializeTransactions(tb)
		if err != nil {
			panic(ts)
		}
		if len(txs) > 0 || len(compaction) > 0 {
			return true
		}
	}
	return false
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
	defer common.Rollback(tx)

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

func buildInsertionSQL(table string, cols []string) string {
	vals := strings.Repeat("?, ", len(cols))
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(cols, ","), vals[:len(vals)-2])
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
	s.mutex.Lock()
	defer s.mutex.Unlock()

	row := s.db.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", k)
	err := row.Scan(&k)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return k, err
}

func (s *SQLite3Store) WriteProperty(ctx context.Context, k, v string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	logger.Printf("SQLite3Store.WriteProperty(%s)", k)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

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

type Row interface {
	Scan(dest ...any) error
}
