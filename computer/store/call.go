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

type SystemCall struct {
	RequestId          string
	UserId             string
	Public             string
	Message            string
	Raw                string
	State              int64
	WithdrawalIds      string
	WithdrawedAt       sql.NullTime
	PreparedMessage    string
	PreparedRaw        string
	PreparedAt         sql.NullTime
	PostProcessMessage string
	PostProcessRaw     string
	PostProcessAt      sql.NullTime
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

var systemCallCols = []string{"request_id", "user_id", "public", "message", "raw", "state", "withdrawal_ids", "withdrawed_at", "prepared_message", "prepared_raw", "prepared_at", "post_process_message", "post_process_raw", "post_process_at", "created_at", "updated_at"}

func (c *SystemCall) GetWithdrawalIds() []string {
	var ids []string
	if c.WithdrawalIds == "" {
		return ids
	}
	return strings.Split(c.WithdrawalIds, ",")
}

func systemCallFromRow(row *sql.Row) (*SystemCall, error) {
	var c SystemCall
	err := row.Scan(&c.RequestId, &c.UserId, &c.Public, &c.Message, &c.Raw, &c.State, &c.WithdrawalIds, &c.WithdrawedAt, &c.PreparedMessage, &c.PreparedRaw, &c.PreparedAt, &c.PostProcessMessage, &c.PostProcessRaw, &c.PostProcessAt, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &c, err
}

func (s *SQLite3Store) WriteUnfinishedSystemCallWithRequest(ctx context.Context, req *Request, call SystemCall, as []*DeployedAsset, txs []*mtg.Transaction, compaction string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.writeDeployedAssetsIfNorExist(ctx, tx, req, as)
	if err != nil {
		return err
	}

	vals := []any{call.RequestId, call.UserId, call.Public, call.Message, call.Raw, call.State, call.WithdrawalIds, call.WithdrawedAt, call.PreparedMessage, call.PreparedRaw, call.PreparedAt, call.PostProcessMessage, call.PostProcessRaw, call.PostProcessAt, call.CreatedAt, call.UpdatedAt}
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

func (s *SQLite3Store) MarkSystemCallWithdrawedWithRequest(ctx context.Context, req *Request, rid string, sessions []*Session) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	now := time.Now().UTC()
	query := "UPDATE system_calls SET withdrawed_at=?, updated_at=? WHERE rid=? AND state=?"
	err = s.execOne(ctx, tx, query, now, now, rid, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE keys %v", err)
	}

	for _, session := range sessions {
		existed, err := s.checkExistence(ctx, tx, "SELECT session_id FROM sessions WHERE session_id=?", session.Id)
		if err != nil || existed {
			return err
		}

		cols := []string{"session_id", "mixin_hash", "mixin_index", "sub_index", "operation", "public",
			"extra", "state", "created_at", "updated_at"}
		vals := []any{session.Id, session.MixinHash, session.MixinIndex, session.Index, session.Operation, session.Public,
			session.Extra, common.RequestStateInitial, session.CreatedAt, session.CreatedAt}
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

func (s *SQLite3Store) MarkSystemCallPreparedWithRequest(ctx context.Context, req *Request, rid string, sessions []*Session) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	now := time.Now().UTC()
	query := "UPDATE system_calls SET prepared_at=?, updated_at=? WHERE rid=? AND state=?"
	err = s.execOne(ctx, tx, query, now, now, rid, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE keys %v", err)
	}

	for _, session := range sessions {
		existed, err := s.checkExistence(ctx, tx, "SELECT session_id FROM sessions WHERE session_id=?", session.Id)
		if err != nil || existed {
			return err
		}

		cols := []string{"session_id", "mixin_hash", "mixin_index", "sub_index", "operation", "public",
			"extra", "state", "created_at", "updated_at"}
		vals := []any{session.Id, session.MixinHash, session.MixinIndex, session.Index, session.Operation, session.Public,
			session.Extra, common.RequestStateInitial, session.CreatedAt, session.CreatedAt}
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

func (s *SQLite3Store) MarkSystemCallDoneWithRequest(ctx context.Context, req *Request, rid string, state int64, sessions []*Session) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	now := time.Now().UTC()
	query := "UPDATE system_calls SET state=?, updated_at=? WHERE rid=? AND state=?"
	err = s.execOne(ctx, tx, query, state, now, rid, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE keys %v", err)
	}

	for _, session := range sessions {
		existed, err := s.checkExistence(ctx, tx, "SELECT session_id FROM sessions WHERE session_id=?", session.Id)
		if err != nil || existed {
			return err
		}

		cols := []string{"session_id", "mixin_hash", "mixin_index", "sub_index", "operation", "public",
			"extra", "state", "created_at", "updated_at"}
		vals := []any{session.Id, session.MixinHash, session.MixinIndex, session.Index, session.Operation, session.Public,
			session.Extra, common.RequestStateInitial, session.CreatedAt, session.CreatedAt}
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

func (s *SQLite3Store) MarkSystemCallProcessedWithRequest(ctx context.Context, req *Request, rid string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE system_calls SET state=?, post_process_at=?, updated_at=? WHERE rid=? AND state=?"
	err = s.execOne(ctx, tx, query, common.RequestStateDone, req.CreatedAt, req.CreatedAt, rid, common.RequestStatePending)
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

func (s *SQLite3Store) ReadSystemCallByRequestId(ctx context.Context, rid string, state int64) (*SystemCall, error) {
	query := fmt.Sprintf("SELECT %s FROM system_calls WHERE request_id=? AND state=?", strings.Join(systemCallCols, ","))
	row := s.db.QueryRowContext(ctx, query, rid, state)

	return systemCallFromRow(row)
}

func (s *SQLite3Store) ReadSystemCallByAnyMessage(ctx context.Context, message string) (*SystemCall, error) {
	query := fmt.Sprintf("SELECT %s FROM system_calls WHERE message=? OR prepared_message=? OR post_process_message=?", strings.Join(systemCallCols, ","))
	row := s.db.QueryRowContext(ctx, query, message)

	return systemCallFromRow(row)
}

func (s *SQLite3Store) ReadSystemCallByPreparedMessage(ctx context.Context, message string, state int64) (*SystemCall, error) {
	query := fmt.Sprintf("SELECT %s FROM system_calls WHERE prepared_message=? AND state=?", strings.Join(systemCallCols, ","))
	row := s.db.QueryRowContext(ctx, query, message, state)

	return systemCallFromRow(row)
}
