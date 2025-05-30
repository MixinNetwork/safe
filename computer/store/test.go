package store

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
)

func (s *SQLite3Store) TestWriteKey(ctx context.Context, id, public string, conf []byte, saved bool) error {
	if !common.CheckTestEnvironment(ctx) {
		return fmt.Errorf("invalid env")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT public FROM keys WHERE public=?", public)
	if err != nil || existed {
		return err
	}

	timestamp := time.Now().UTC()
	share := common.Base91Encode(conf)
	fingerprint := hex.EncodeToString(common.Fingerprint(public))
	cols := []string{"public", "fingerprint", "share", "session_id", "created_at", "updated_at", "confirmed_at"}
	values := []any{public, fingerprint, share, id, timestamp, timestamp, timestamp}
	if saved {
		cols = append(cols, "backed_up_at")
		values = append(values, timestamp)
	}

	err = s.execOne(ctx, tx, buildInsertionSQL("keys", cols), values...)
	if err != nil {
		return fmt.Errorf("SQLite3Store INSERT keys %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) TestWriteCall(ctx context.Context, call *SystemCall) error {
	if !common.CheckTestEnvironment(ctx) {
		panic(ctx)
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	vals := []any{call.RequestId, call.Superior, call.RequestHash, call.Type, call.NonceAccount, call.Public, call.SkipPostProcess, call.MessageHash, call.Raw, call.State, call.WithdrawalTraces, call.Signature, call.RequestSignerAt, call.Hash, call.CreatedAt, call.UpdatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("system_calls", systemCallCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT system_calls %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) TestWriteSignSession(ctx context.Context, call *SystemCall, sessions []*Session) error {
	if !common.CheckTestEnvironment(ctx) {
		panic(ctx)
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	now := time.Now().UTC()
	query := "UPDATE system_calls SET request_signer_at=?, updated_at=? WHERE id=? AND state=? AND signature IS NULL"
	err = s.execOne(ctx, tx, query, now, now, call.RequestId, common.RequestStatePending)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE keys %v", err)
	}

	for _, session := range sessions {
		err = s.writeSession(ctx, tx, session)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) TestReadPendingRequest(ctx context.Context) (*Request, error) {
	query := fmt.Sprintf("SELECT %s FROM requests WHERE state=? ORDER BY created_at ASC, request_id ASC LIMIT 1", strings.Join(requestCols, ","))
	row := s.db.QueryRowContext(ctx, query, common.RequestStateInitial)

	return requestFromRow(row)
}
