package store

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/common"
)

func (s *SQLite3Store) PrepareSessionSignerIfNotExist(ctx context.Context, sessionId, signerId string, createdAt time.Time) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "SELECT extra FROM session_signers WHERE session_id=? AND signer_id=?"
	existed, err := s.checkExistence(ctx, tx, query, sessionId, signerId)
	if err != nil || existed {
		return err
	}

	cols := []string{"session_id", "signer_id", "extra", "created_at", "updated_at"}
	err = s.execOne(ctx, tx, buildInsertionSQL("session_signers", cols),
		sessionId, signerId, "", createdAt, createdAt)
	if err != nil {
		return fmt.Errorf("SQLite3Store INSERT session_signers %v", err)
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
