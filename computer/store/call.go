package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
)

const (
	CallTypeMint        = "mint"
	CallTypeMain        = "main"
	CallTypePrepare     = "prepare"
	CallTypePostProcess = "post_process"
)

type SystemCall struct {
	RequestId        string
	Superior         string
	Type             string
	NonceAccount     string
	Public           string
	SkipPostprocess  bool
	Message          string
	Raw              string
	State            int64
	WithdrawalTraces sql.NullString
	WithdrawnAt      sql.NullTime
	Signature        sql.NullString
	RequestSignerAt  sql.NullTime
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type SpentReference struct {
	TransactionHash string
	RequestId       string
	ChainId         string
	AssetId         string
	Amount          string
	CreatedAt       time.Time

	Asset *bot.AssetNetwork
}

var systemCallCols = []string{"request_id", "superior_request_id", "call_type", "nonce_account", "public", "skip_postprocess", "message", "raw", "state", "withdrawal_traces", "withdrawn_at", "signature", "request_signer_at", "created_at", "updated_at"}

var spentReferenceCols = []string{"transaction_hash", "request_id", "chain_id", "asset_id", "amount", "created_at"}

func systemCallFromRow(row Row) (*SystemCall, error) {
	var c SystemCall
	err := row.Scan(&c.RequestId, &c.Superior, &c.Type, &c.NonceAccount, &c.Public, &c.SkipPostprocess, &c.Message, &c.Raw, &c.State, &c.WithdrawalTraces, &c.WithdrawnAt, &c.Signature, &c.RequestSignerAt, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &c, err
}

func (c *SystemCall) GetWithdrawalIds() []string {
	if !c.WithdrawalTraces.Valid {
		return []string{}
	}
	return mtg.SplitIds(c.WithdrawalTraces.String)
}

func (c *SystemCall) UserIdFromPublicPath() *big.Int {
	data := common.DecodeHexOrPanic(c.Public)
	if len(data) != 16 {
		panic(fmt.Errorf("invalid public of system call: %v", c))
	}
	if bytes.Equal(data[8:], DefaultPath) {
		panic(fmt.Errorf("invalid user id"))
	}
	id := new(big.Int).SetBytes(data[8:])
	return id
}

func (s *SQLite3Store) WriteInitialSystemCallWithRequest(ctx context.Context, req *Request, call *SystemCall, rs []*SpentReference, txs []*mtg.Transaction, compaction string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	vals := []any{call.RequestId, call.Superior, call.Type, call.NonceAccount, call.Public, call.SkipPostprocess, call.Message, call.Raw, call.State, call.WithdrawalTraces, call.WithdrawnAt, call.Signature, call.RequestSignerAt, call.CreatedAt, call.UpdatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("system_calls", systemCallCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT system_calls %v", err)
	}

	for _, r := range rs {
		vals := []any{r.TransactionHash, r.RequestId, r.ChainId, r.AssetId, r.Amount, req.CreatedAt}
		err = s.execOne(ctx, tx, buildInsertionSQL("spent_references", spentReferenceCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT spent_references %v", err)
		}
	}

	err = s.finishRequest(ctx, tx, req, txs, compaction)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) WriteSubCallWithRequest(ctx context.Context, req *Request, call *SystemCall, txs []*mtg.Transaction, compaction string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	vals := []any{call.RequestId, call.Superior, call.Type, call.NonceAccount, call.Public, call.SkipPostprocess, call.Message, call.Raw, call.State, call.WithdrawalTraces, call.WithdrawnAt, call.Signature, call.RequestSignerAt, call.CreatedAt, call.UpdatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("system_calls", systemCallCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT system_calls %v", err)
	}

	err = s.finishRequest(ctx, tx, req, txs, compaction)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) WriteMintCallWithRequest(ctx context.Context, req *Request, call *SystemCall, session *Session, assets map[string]*solanaApp.DeployedAsset) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	vals := []any{call.RequestId, call.Superior, call.Type, call.NonceAccount, call.Public, call.SkipPostprocess, call.Message, call.Raw, call.State, call.WithdrawalTraces, call.WithdrawnAt, call.Signature, call.RequestSignerAt, call.CreatedAt, call.UpdatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("system_calls", systemCallCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT system_calls %v", err)
	}

	cols := []string{"session_id", "request_id", "mixin_hash", "mixin_index", "sub_index", "operation", "public",
		"extra", "state", "created_at", "updated_at"}
	vals = []any{session.Id, session.RequestId, session.MixinHash, session.MixinIndex, session.Index, session.Operation, session.Public,
		session.Extra, common.RequestStateInitial, session.CreatedAt, session.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("sessions", cols), vals...)
	if err != nil {
		return fmt.Errorf("SQLite3Store INSERT sessions %v", err)
	}

	for _, asset := range assets {
		existed, err := s.checkExistence(ctx, tx, "SELECT address FROM deployed_assets WHERE asset_id=?", asset.AssetId)
		if err != nil {
			return err
		}
		if existed {
			continue
		}

		vals := []any{asset.AssetId, asset.Address, common.RequestStateInitial, req.CreatedAt}
		err = s.execOne(ctx, tx, buildInsertionSQL("deployed_assets", deployedAssetCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT deployed_assets %v", err)
		}
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) UpdateWithdrawalsWithRequest(ctx context.Context, req *Request, call *SystemCall, txs []*mtg.Transaction, compaction string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE system_calls SET withdrawal_traces=?, withdrawn_at=?, updated_at=? WHERE request_id=? AND state=? AND withdrawal_traces IS NULL AND withdrawn_at IS NULL"
	_, err = tx.ExecContext(ctx, query, call.WithdrawalTraces, call.WithdrawnAt, req.CreatedAt, call.RequestId, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
	}

	err = s.finishRequest(ctx, tx, req, txs, compaction)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite3Store) MarkSystemCallWithdrawnWithRequest(ctx context.Context, req *Request, call *SystemCall, txId, hash string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE system_calls SET state=?, withdrawal_traces=?, withdrawn_at=?, updated_at=? WHERE request_id=? AND state=?"
	_, err = tx.ExecContext(ctx, query, call.State, call.WithdrawalTraces, call.WithdrawnAt, req.CreatedAt, call.RequestId, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
	}

	err = s.writeConfirmedWithdrawal(ctx, tx, req, txId, hash, call.RequestId)
	if err != nil {
		return err
	}
	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ConfirmSystemCallSuccessWithRequest(ctx context.Context, req *Request, call *SystemCall, assets []string, txs []*mtg.Transaction, compaction string) error {
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
	if call.Type == CallTypeMint {
		for _, asset := range assets {
			query := "UPDATE deployed_assets SET state=? WHERE address=? AND state=?"
			err = s.execOne(ctx, tx, query, common.RequestStateDone, asset, common.RequestStateInitial)
			if err != nil {
				return fmt.Errorf("SQLite3Store UPDATE deployed_assets %v", err)
			}
		}
	}

	err = s.finishRequest(ctx, tx, req, txs, compaction)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ConfirmSystemCallFailWithRequest(ctx context.Context, req *Request, call *SystemCall, txs []*mtg.Transaction) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE system_calls SET state=?, updated_at=? WHERE request_id=? AND state=?"
	err = s.execOne(ctx, tx, query, common.RequestStateFailed, req.CreatedAt, call.RequestId, call.State)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
	}

	err = s.finishRequest(ctx, tx, req, txs, "")
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

	query := "UPDATE system_calls SET request_signer_at=?, updated_at=? WHERE request_id=? AND state=? AND signature IS NULL"
	err = s.execOne(ctx, tx, query, req.CreatedAt, req.CreatedAt, call.RequestId, common.RequestStatePending)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE system_calls %v", err)
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

	err = s.finishRequest(ctx, tx, req, nil, "")
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

func (s *SQLite3Store) ListUnconfirmedSystemCalls(ctx context.Context) ([]*SystemCall, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sql := fmt.Sprintf("SELECT %s FROM system_calls WHERE state=? AND withdrawal_traces IS NULL AND withdrawn_at IS NULL ORDER BY created_at ASC LIMIT 100", strings.Join(systemCallCols, ","))
	rows, err := s.db.QueryContext(ctx, sql, common.RequestStateInitial)
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

func (s *SQLite3Store) ListInitialSystemCalls(ctx context.Context) ([]*SystemCall, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sql := fmt.Sprintf("SELECT %s FROM system_calls WHERE state=? AND withdrawal_traces='' AND withdrawn_at IS NOT NULL AND signature IS NULL ORDER BY created_at ASC LIMIT 100", strings.Join(systemCallCols, ","))
	rows, err := s.db.QueryContext(ctx, sql, common.RequestStateInitial)
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

	sql := fmt.Sprintf("SELECT %s FROM system_calls WHERE state!=? AND withdrawal_traces='' AND withdrawn_at IS NOT NULL AND signature IS NULL ORDER BY created_at ASC LIMIT 1", strings.Join(systemCallCols, ","))
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

func (s *SQLite3Store) CheckReferencesSpent(ctx context.Context, rs []*SpentReference) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer common.Rollback(tx)

	for _, ref := range rs {
		existed, err := s.checkExistence(ctx, tx, "SELECT transaction_hash FROM spent_references WHERE transaction_hash=?", ref.TransactionHash)
		if err != nil {
			return "", err
		}
		if existed {
			return ref.TransactionHash, nil
		}
	}
	return "", nil
}
