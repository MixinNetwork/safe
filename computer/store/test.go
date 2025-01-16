package store

import (
	"context"
	"encoding/hex"
	"fmt"
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

	vals := []any{call.RequestId, call.Superior, call.Type, call.NonceAccount, call.Public, call.Message, call.Raw, call.State, call.WithdrawalIds, call.WithdrawedAt, call.Signature, call.RequestSignerAt, call.CreatedAt, call.UpdatedAt}
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
	query := "UPDATE system_calls SET request_signer_at=?, updated_at=? WHERE request_id=? AND state=? AND signature IS NULL"
	err = s.execOne(ctx, tx, query, now, now, call.RequestId, common.RequestStatePending)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE keys %v", err)
	}

	for _, session := range sessions {
		cols := []string{"session_id", "request_id", "mixin_hash", "mixin_index", "sub_index", "operation", "public",
			"extra", "state", "created_at", "updated_at"}
		vals := []any{session.Id, session.RequestId, session.MixinHash, session.MixinIndex, session.Index, session.Operation, session.Public,
			session.Extra, common.RequestStateInitial, session.CreatedAt, session.CreatedAt}
		err = s.execOne(ctx, tx, buildInsertionSQL("sessions", cols), vals...)
		if err != nil {
			return fmt.Errorf("SQLite3Store INSERT sessions %v", err)
		}
	}

	return tx.Commit()
}
