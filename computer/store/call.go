package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
)

const (
	CallTypeMain        = "main"
	CallTypePrepare     = "prepare"
	CallTypePostProcess = "post_process"
)

type SystemCall struct {
	RequestId       string
	Superior        string
	Type            string
	NonceAccount    string
	Public          string
	Message         string
	Raw             string
	State           int64
	WithdrawalIds   string
	WithdrawedAt    sql.NullTime
	Signature       sql.NullString
	RequestSignerAt sql.NullTime
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

var systemCallCols = []string{"request_id", "superior_request_id", "call_type", "nonce_account", "public", "message", "raw", "state", "withdrawal_ids", "withdrawed_at", "signature", "request_signer_at", "created_at", "updated_at"}

func systemCallFromRow(row Row) (*SystemCall, error) {
	var c SystemCall
	err := row.Scan(&c.RequestId, &c.Superior, &c.Type, &c.NonceAccount, &c.Public, &c.Message, &c.Raw, &c.State, &c.WithdrawalIds, &c.WithdrawedAt, &c.Signature, &c.RequestSignerAt, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &c, err
}

func (c *SystemCall) GetWithdrawalIds() []string {
	var ids []string
	if c.WithdrawalIds == "" {
		return ids
	}
	return strings.Split(c.WithdrawalIds, ",")
}

func (s *SQLite3Store) WriteInitialSystemCallWithRequest(ctx context.Context, req *Request, call *SystemCall, txs []*mtg.Transaction, compaction string) error {
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

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?", common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}
	err = s.writeActionResult(ctx, tx, req.Output.OutputId, compaction, txs, req.Id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) WriteSubCallAndAssetsWithRequest(ctx context.Context, req *Request, call *SystemCall, assets []*DeployedAsset, txs []*mtg.Transaction, compaction string) error {
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

	err = s.writeDeployedAssetsIfNorExist(ctx, tx, req, assets)
	if err != nil {
		return err
	}
	err = s.assignNonceAccountToCall(ctx, tx, req, call)
	if err != nil {
		return err
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?", common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}
	err = s.writeActionResult(ctx, tx, req.Output.OutputId, compaction, txs, req.Id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) MarkSystemCallWithdrawedWithRequest(ctx context.Context, req *Request, call *SystemCall, txId string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE system_calls SET state=?, withdrawal_ids=?, withdrawed_at=?, updated_at=? WHERE request_id=? AND state=?"
	_, err = tx.ExecContext(ctx, query, call.State, call.WithdrawalIds, call.WithdrawedAt, req.CreatedAt, call.RequestId, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE keys %v", err)
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

func (s *SQLite3Store) ConfirmSystemCallWithRequest(ctx context.Context, req *Request, call *SystemCall, hash string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE system_calls SET state=?, updated_at=? WHERE request_id=? AND state=?"
	err = s.execOne(ctx, tx, query, common.RequestStateDone, req.CreatedAt, call.RequestId, common.RequestStatePending)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
	}
	if call.Type == CallTypePrepare {
		query := "UPDATE system_calls SET state=?, updated_at=? WHERE request_id=? AND state=?"
		err = s.execOne(ctx, tx, query, common.RequestStatePending, req.CreatedAt, call.Superior, common.RequestStateInitial)
		if err != nil {
			return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
		}
	}
	query = "UPDATE nonce_accounts SET hash=?, call_id=?, updated_at=? WHERE address=? AND call_id=? AND user_id IS NULL"
	err = s.execOne(ctx, tx, query, hash, nil, req.CreatedAt, call.NonceAccount, call.RequestId)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE nonce_accounts %v", err)
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

func (s *SQLite3Store) RequestSignerSignForCall(ctx context.Context, call *SystemCall, sessions []*Session) error {
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

func (s *SQLite3Store) AttachSystemCallSignatureWithRequest(ctx context.Context, req *Request, call *SystemCall, sid, signature string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE system_calls SET signature=?, updated_at=? WHERE request_id=? AND state=? AND signature IS NULL"
	err = s.execOne(ctx, tx, query, signature, time.Now().UTC(), call.RequestId, common.RequestStatePending)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
	}
	query = "UPDATE sessions SET state=?, updated_at=? WHERE session_id=?"
	err = s.execOne(ctx, tx, query, common.RequestStateDone, time.Now().UTC(), sid)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE sessions %v", err)
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

func (s *SQLite3Store) ReadSystemCallByRequestId(ctx context.Context, rid string, state int64) (*SystemCall, error) {
	query := fmt.Sprintf("SELECT %s FROM system_calls WHERE request_id=?", strings.Join(systemCallCols, ","))
	values := []any{rid}
	if state > 0 {
		query += " AND state=?"
		values = append(values, state)
	}

	row := s.db.QueryRowContext(ctx, query, values...)

	return systemCallFromRow(row)
}

func (s *SQLite3Store) ReadInitialSystemCallBySuperior(ctx context.Context, rid string) (*SystemCall, error) {
	query := fmt.Sprintf("SELECT %s FROM system_calls WHERE superior_request_id=? AND state=? ORDER BY created_at ASC LIMIT 1", strings.Join(systemCallCols, ","))
	row := s.db.QueryRowContext(ctx, query, rid, common.RequestStateInitial)

	return systemCallFromRow(row)
}

func (s *SQLite3Store) ReadSystemCallByMessage(ctx context.Context, message string) (*SystemCall, error) {
	query := fmt.Sprintf("SELECT %s FROM system_calls WHERE message=?", strings.Join(systemCallCols, ","))
	row := s.db.QueryRowContext(ctx, query, message)

	return systemCallFromRow(row)
}

func (s *SQLite3Store) ListInitialSystemCalls(ctx context.Context) ([]*SystemCall, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sql := fmt.Sprintf("SELECT %s FROM system_calls WHERE state=? AND withdrawal_ids='' AND withdrawed_at IS NOT NULL AND signature IS NULL ORDER BY created_at ASC LIMIT 100", strings.Join(systemCallCols, ","))
	rows, err := s.db.QueryContext(ctx, sql, common.RequestStateDone)
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

func (s *SQLite3Store) ListUnsignedCalls(ctx context.Context) ([]*SystemCall, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sql := fmt.Sprintf("SELECT %s FROM system_calls WHERE state=? AND signature IS NULL ORDER BY created_at ASC LIMIT 100", strings.Join(systemCallCols, ","))
	rows, err := s.db.QueryContext(ctx, sql, common.RequestStatePending)
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

func (s *SQLite3Store) ListSignedCalls(ctx context.Context) ([]*SystemCall, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sql := fmt.Sprintf("SELECT %s FROM system_calls WHERE state=? AND signature IS NOT NULL ORDER BY created_at ASC LIMIT 100", strings.Join(systemCallCols, ","))
	rows, err := s.db.QueryContext(ctx, sql, common.RequestStatePending)
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

func (s *SQLite3Store) ListUnfinishedSubSystemCalls(ctx context.Context) ([]*SystemCall, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sql := fmt.Sprintf("SELECT %s FROM system_calls WHERE state!=? AND withdrawal_ids='' AND withdrawed_at IS NOT NULL AND signature IS NULL ORDER BY created_at ASC LIMIT 1", strings.Join(systemCallCols, ","))
	rows, err := s.db.QueryContext(ctx, sql, common.RequestStateDone)
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
