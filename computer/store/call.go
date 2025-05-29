package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/MixinNetwork/safe/util"
	"github.com/gagliardetto/solana-go"
)

const (
	CallTypeDeposit     = "deposit"
	CallTypeMain        = "main"
	CallTypePrepare     = "prepare"
	CallTypePostProcess = "post_process"
)

type SystemCall struct {
	RequestId        string
	Superior         string
	RequestHash      string
	Type             string
	NonceAccount     string
	Public           string
	SkipPostProcess  bool
	MessageHash      string
	Raw              string
	State            int64
	WithdrawalTraces sql.NullString
	Signature        sql.NullString
	RequestSignerAt  sql.NullTime
	Hash             sql.NullString
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

var systemCallCols = []string{"id", "superior_id", "request_hash", "call_type", "nonce_account", "public", "skip_postprocess", "message_hash", "raw", "state", "withdrawal_traces", "signature", "request_signer_at", "hash", "created_at", "updated_at"}

func systemCallFromRow(row Row) (*SystemCall, error) {
	var c SystemCall
	err := row.Scan(&c.RequestId, &c.Superior, &c.RequestHash, &c.Type, &c.NonceAccount, &c.Public, &c.SkipPostProcess, &c.MessageHash, &c.Raw, &c.State, &c.WithdrawalTraces, &c.Signature, &c.RequestSignerAt, &c.Hash, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &c, err
}

func (c *SystemCall) GetWithdrawalIds() []string {
	return util.SplitIds(c.WithdrawalTraces.String, ",")
}

func (c *SystemCall) UserIdFromPublicPath() string {
	data := common.DecodeHexOrPanic(c.Public)
	if len(data) != 16 {
		panic(fmt.Errorf("invalid public of system call: %v", c))
	}
	if bytes.Equal(data[8:], DefaultPath) {
		panic(fmt.Errorf("invalid user id"))
	}
	id := new(big.Int).SetBytes(data[8:])
	return id.String()
}

func (c *SystemCall) MessageBytes() []byte {
	tx, err := solana.TransactionFromBase64(c.Raw)
	if err != nil {
		panic(err)
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return msg
}

func (c *SystemCall) MessageHex() string {
	return hex.EncodeToString(c.MessageBytes())
}

func (s *SQLite3Store) WriteInitialSystemCallWithRequest(ctx context.Context, req *Request, call *SystemCall, os []*UserOutput) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.writeSystemCall(ctx, tx, call)
	if err != nil {
		return err
	}

	for _, o := range os {
		query := "UPDATE user_outputs SET state=?, signed_by=?, updated_at=? WHERE output_id=? AND state=? AND user_id=?"
		err = s.execOne(ctx, tx, query, common.RequestStatePending, call.RequestId, req.CreatedAt, o.OutputId, common.RequestStateInitial, call.UserIdFromPublicPath())
		if err != nil {
			return fmt.Errorf("SQLite3Store UPDATE user_outputs %v", err)
		}
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) WriteDepositCallWithRequest(ctx context.Context, req *Request, call *SystemCall, session *Session) error {
	if call.Type != CallTypeDeposit {
		panic(call.Type)
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.writeSystemCall(ctx, tx, call)
	if err != nil {
		return err
	}
	err = s.writeSession(ctx, tx, session)
	if err != nil {
		return err
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ConfirmNonceAvailableWithRequest(ctx context.Context, req *Request, call, sub *SystemCall, sessions []*Session, txs []*mtg.Transaction, compaction string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE system_calls SET state=?, withdrawal_traces=?, request_signer_at=?, updated_at=? WHERE id=? AND state=? AND withdrawal_traces IS NULL"
	_, err = tx.ExecContext(ctx, query, call.State, call.WithdrawalTraces, call.RequestSignerAt, req.CreatedAt, call.RequestId, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
	}

	if sub != nil {
		err = s.writeSystemCall(ctx, tx, sub)
		if err != nil {
			return err
		}
	}

	for _, session := range sessions {
		err = s.writeSession(ctx, tx, session)
		if err != nil {
			return err
		}
	}

	err = s.finishRequest(ctx, tx, req, txs, compaction)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite3Store) RefundOutputsWithRequest(ctx context.Context, req *Request, call *SystemCall, os []*UserOutput, txs []*mtg.Transaction, compaction string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	if call != nil {
		query := "UPDATE system_calls SET state=?, updated_at=? WHERE id=? AND state=? AND withdrawal_traces IS NULL"
		_, err = tx.ExecContext(ctx, query, common.RequestStateFailed, req.CreatedAt, call.RequestId, common.RequestStateInitial)
		if err != nil {
			return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
		}
	}

	for _, o := range os {
		query := "UPDATE user_outputs SET state=?, updated_at=? WHERE output_id=? AND state!=? AND signed_by IS NULL"
		err = s.execOne(ctx, tx, query, common.RequestStateDone, req.CreatedAt, o.OutputId, common.RequestStateDone)
		if err != nil {
			return fmt.Errorf("SQLite3Store UPDATE user_outputs %v", err)
		}
	}

	err = s.finishRequest(ctx, tx, req, txs, compaction)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite3Store) ConfirmSystemCallsWithRequest(ctx context.Context, req *Request, calls []*SystemCall, sub *SystemCall, session *Session, os []*UserOutput) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	for _, call := range calls {
		query := "UPDATE system_calls SET state=?, hash=?, updated_at=? WHERE id=? AND state=?"
		err = s.execOne(ctx, tx, query, call.State, call.Hash, req.CreatedAt, call.RequestId, common.RequestStatePending)
		if err != nil {
			return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
		}
	}

	if sub != nil && session != nil {
		err = s.writeSystemCall(ctx, tx, sub)
		if err != nil {
			return err
		}

		err = s.writeSession(ctx, tx, session)
		if err != nil {
			return err
		}
	}

	for _, o := range os {
		query := "UPDATE user_outputs SET state=?, updated_at=? WHERE output_id=? AND state=?"
		err = s.execOne(ctx, tx, query, common.RequestStateDone, req.CreatedAt, o.OutputId, common.RequestStatePending)
		if err != nil {
			return fmt.Errorf("SQLite3Store UPDATE user_outputs %v", err)
		}
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ConfirmPostProcessSystemCallWithRequest(ctx context.Context, req *Request, call *SystemCall, txs []*mtg.Transaction) error {
	if call.Type != CallTypePostProcess {
		panic(call.Type)
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE system_calls SET state=?, hash=?, updated_at=? WHERE id=? AND state=?"
	err = s.execOne(ctx, tx, query, call.State, call.Hash, req.CreatedAt, call.RequestId, common.RequestStatePending)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
	}

	err = s.finishRequest(ctx, tx, req, txs, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) FailSystemCallWithRequest(ctx context.Context, req *Request, call, sub *SystemCall, session *Session, os []*UserOutput) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE system_calls SET state=?, updated_at=? WHERE id=? AND state=?"
	err = s.execOne(ctx, tx, query, common.RequestStateFailed, req.CreatedAt, call.RequestId, common.RequestStatePending)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
	}

	// if a main system call failed, its prepare call must success
	if call.Type == CallTypeMain {
		query = "UPDATE system_calls SET state=?, updated_at=? WHERE superior_id=? AND call_type=? AND state=?"
		_, err = tx.ExecContext(ctx, query, common.RequestStateDone, req.CreatedAt, call.RequestId, CallTypePrepare, common.RequestStatePending)
		if err != nil {
			return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
		}
	}
	// if a prepare system call failed, fail its main call
	if call.Type == CallTypePrepare {
		query = "UPDATE system_calls SET state=?, updated_at=? WHERE superior_id=? AND call_type=? AND state=?"
		_, err = tx.ExecContext(ctx, query, common.RequestStateFailed, req.CreatedAt, call.Superior, CallTypeMain, common.RequestStatePending)
		if err != nil {
			return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
		}
	}

	if sub != nil {
		err = s.writeSystemCall(ctx, tx, sub)
		if err != nil {
			return err
		}

		err = s.writeSession(ctx, tx, session)
		if err != nil {
			return err
		}
	}

	for _, o := range os {
		query := "UPDATE user_outputs SET state=?, updated_at=? WHERE output_id=? AND state=?"
		err = s.execOne(ctx, tx, query, common.RequestStateDone, req.CreatedAt, o.OutputId, common.RequestStatePending)
		if err != nil {
			return fmt.Errorf("SQLite3Store UPDATE user_outputs %v", err)
		}
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) WriteSignSessionWithRequest(ctx context.Context, req *Request, call *SystemCall, sessions []*Session) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE system_calls SET request_signer_at=?, updated_at=? WHERE id=? AND state!=? AND signature IS NULL"
	err = s.execOne(ctx, tx, query, req.CreatedAt, req.CreatedAt, call.RequestId, common.RequestStateFailed)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
	}

	for _, session := range sessions {
		err = s.writeSession(ctx, tx, session)
		if err != nil {
			return err
		}
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) AttachSystemCallSignatureWithRequest(ctx context.Context, req *Request, call *SystemCall, sid, signature string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE system_calls SET signature=?, updated_at=? WHERE id=? AND state!=? AND signature IS NULL"
	err = s.execOne(ctx, tx, query, signature, time.Now().UTC(), call.RequestId, common.RequestStateFailed)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
	}
	query = "UPDATE sessions SET state=?, updated_at=? WHERE session_id=?"
	err = s.execOne(ctx, tx, query, common.RequestStateDone, time.Now().UTC(), sid)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE sessions %v", err)
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadSystemCallByRequestId(ctx context.Context, rid string, state int64) (*SystemCall, error) {
	query := fmt.Sprintf("SELECT %s FROM system_calls WHERE id=?", strings.Join(systemCallCols, ","))
	values := []any{rid}
	if state > 0 {
		query += " AND state=?"
		values = append(values, state)
	}

	row := s.db.QueryRowContext(ctx, query, values...)

	return systemCallFromRow(row)
}

func (s *SQLite3Store) ReadInitialSystemCallBySuperior(ctx context.Context, rid string) (*SystemCall, error) {
	query := fmt.Sprintf("SELECT %s FROM system_calls WHERE superior_id=? AND state=? ORDER BY created_at ASC LIMIT 1", strings.Join(systemCallCols, ","))
	row := s.db.QueryRowContext(ctx, query, rid, common.RequestStateInitial)

	return systemCallFromRow(row)
}

func (s *SQLite3Store) ReadSystemCallByMessage(ctx context.Context, messageHash string) (*SystemCall, error) {
	query := fmt.Sprintf("SELECT %s FROM system_calls WHERE message_hash=?", strings.Join(systemCallCols, ","))
	row := s.db.QueryRowContext(ctx, query, messageHash)

	return systemCallFromRow(row)
}

func (s *SQLite3Store) ReadSystemCallByHash(ctx context.Context, hash string) (*SystemCall, error) {
	query := fmt.Sprintf("SELECT %s FROM system_calls WHERE hash=?", strings.Join(systemCallCols, ","))
	row := s.db.QueryRowContext(ctx, query, hash)

	return systemCallFromRow(row)
}

func (s *SQLite3Store) ListUnconfirmedSystemCalls(ctx context.Context) ([]*SystemCall, error) {
	query := fmt.Sprintf("SELECT %s FROM system_calls WHERE state=? AND withdrawal_traces IS NULL ORDER BY created_at ASC LIMIT 100", strings.Join(systemCallCols, ","))
	return s.listSystemCallsByQuery(ctx, query, common.RequestStateInitial)
}

func (s *SQLite3Store) ListUnsignedCalls(ctx context.Context) ([]*SystemCall, error) {
	query := fmt.Sprintf("SELECT %s FROM system_calls WHERE state!=? AND withdrawal_traces IS NOT NULL AND signature IS NULL ORDER BY created_at ASC LIMIT 100", strings.Join(systemCallCols, ","))
	return s.listSystemCallsByQuery(ctx, query, common.RequestStateFailed)
}

func (s *SQLite3Store) ListSignedCalls(ctx context.Context) (map[string]*SystemCall, error) {
	query := fmt.Sprintf("SELECT %s FROM system_calls WHERE state=? AND signature IS NOT NULL ORDER BY created_at ASC LIMIT 100", strings.Join(systemCallCols, ","))
	calls, err := s.listSystemCallsByQuery(ctx, query, common.RequestStatePending)
	if err != nil {
		return nil, err
	}

	callMap := make(map[string]*SystemCall)
	for _, call := range calls {
		callMap[call.RequestId] = call
	}
	return callMap, nil
}

func (s *SQLite3Store) listSystemCallsByQuery(ctx context.Context, query string, params ...any) ([]*SystemCall, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	rows, err := s.db.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var calls []*SystemCall
	for rows.Next() {
		call, err := systemCallFromRow(rows)
		if err != nil {
			return nil, err
		}
		calls = append(calls, call)
	}
	return calls, nil
}

func (s *SQLite3Store) CountUserSystemCallByState(ctx context.Context, state byte) (int, error) {
	query := "SELECT COUNT(*) FROM system_calls where call_type=? AND state=?"
	row := s.db.QueryRowContext(ctx, query, CallTypeMain, state)

	var count int
	err := row.Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

func (s *SQLite3Store) CheckUnfinishedSubCalls(ctx context.Context, call *SystemCall) (bool, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer common.Rollback(tx)

	return s.checkExistence(ctx, tx, "SELECT id FROM system_calls WHERE call_type=? AND state=? AND superior_id=?", CallTypePrepare, common.RequestStatePending, call.RequestId)
}

func (s *SQLite3Store) writeSystemCall(ctx context.Context, tx *sql.Tx, call *SystemCall) error {
	vals := []any{call.RequestId, call.Superior, call.RequestHash, call.Type, call.NonceAccount, call.Public, call.SkipPostProcess, call.MessageHash, call.Raw, call.State, call.WithdrawalTraces, call.Signature, call.RequestSignerAt, call.Hash, call.CreatedAt, call.UpdatedAt}
	err := s.execOne(ctx, tx, buildInsertionSQL("system_calls", systemCallCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT system_calls %v", err)
	}
	return nil
}
