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

type SafeProposal struct {
	RequestId string
	Chain     byte
	Holder    string
	Signer    string
	Observer  string
	Timelock  time.Duration
	Path      string
	Address   string
	Extra     []byte
	Receivers []string
	Threshold byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Safe struct {
	Holder      string
	Chain       byte
	Signer      string
	Observer    string
	Timelock    time.Duration
	Path        string
	Address     string
	Extra       []byte
	Receivers   []string
	Threshold   byte
	RequestId   string
	Nonce       int64
	State       byte
	SafeAssetId string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

var safeCols = []string{"holder", "chain", "signer", "observer", "timelock", "path", "address", "extra", "receivers", "threshold", "request_id", "nonce", "state", "safe_asset_id", "created_at", "updated_at"}

var safeProposalCols = []string{"request_id", "chain", "holder", "signer", "observer", "timelock", "path", "address", "extra", "receivers", "threshold", "created_at", "updated_at"}

func (s *Safe) values() []any {
	return []any{s.Holder, s.Chain, s.Signer, s.Observer, s.Timelock, s.Path, s.Address, s.Extra, strings.Join(s.Receivers, ";"), s.Threshold, s.RequestId, s.Nonce, s.State, s.SafeAssetId, s.CreatedAt, s.UpdatedAt}
}

func (s *SafeProposal) values() []any {
	return []any{s.RequestId, s.Chain, s.Holder, s.Signer, s.Observer, s.Timelock, s.Path, s.Address, s.Extra, strings.Join(s.Receivers, ";"), s.Threshold, s.CreatedAt, s.UpdatedAt}
}

func safeFromRow(row *sql.Row) (*Safe, error) {
	var s Safe
	var receivers string
	err := row.Scan(&s.Holder, &s.Chain, &s.Signer, &s.Observer, &s.Timelock, &s.Path, &s.Address, &s.Extra, &receivers, &s.Threshold, &s.RequestId, &s.Nonce, &s.State, &s.SafeAssetId, &s.CreatedAt, &s.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	s.Receivers = strings.Split(receivers, ";")
	return &s, err
}

func safeProposalFromRow(row *sql.Row) (*SafeProposal, error) {
	var s SafeProposal
	var receivers string
	err := row.Scan(&s.RequestId, &s.Chain, &s.Holder, &s.Signer, &s.Observer, &s.Timelock, &s.Path, &s.Address, &s.Extra, &receivers, &s.Threshold, &s.CreatedAt, &s.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	s.Receivers = strings.Split(receivers, ";")
	return &s, err
}

func (s *SQLite3Store) ReadSafeProposal(ctx context.Context, requestId string) (*SafeProposal, error) {
	query := fmt.Sprintf("SELECT %s FROM safe_proposals WHERE request_id=?", strings.Join(safeProposalCols, ","))
	row := s.db.QueryRowContext(ctx, query, requestId)
	return safeProposalFromRow(row)
}

func (s *SQLite3Store) ReadSafeProposalByAddress(ctx context.Context, addr string) (*SafeProposal, error) {
	query := fmt.Sprintf("SELECT %s FROM safe_proposals WHERE address=?", strings.Join(safeProposalCols, ","))
	row := s.db.QueryRowContext(ctx, query, addr)
	return safeProposalFromRow(row)
}

func (s *SQLite3Store) WriteSafeProposalWithRequest(ctx context.Context, sp *SafeProposal, txs []*mtg.Transaction, req *common.Request) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.execOne(ctx, tx, buildInsertionSQL("safe_proposals", safeProposalCols), sp.values()...)
	if err != nil {
		return fmt.Errorf("INSERT safe_proposals %v", err)
	}
	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), sp.RequestId)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	err = s.writeActionResult(ctx, tx, req.Output.OutputId, "", txs, sp.RequestId)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite3Store) WriteEthereumSafeProposalWithRequest(ctx context.Context, sp *SafeProposal, trx *Transaction, txs []*mtg.Transaction, req *common.Request) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.execOne(ctx, tx, buildInsertionSQL("safe_proposals", safeProposalCols), sp.values()...)
	if err != nil {
		return fmt.Errorf("INSERT safe_proposals %v", err)
	}

	vals := []any{trx.TransactionHash, trx.RawTransaction, trx.Holder, trx.Chain, trx.AssetId, trx.State, trx.Data, trx.RequestId, trx.CreatedAt, trx.UpdatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("transactions", transactionCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT transactions %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), sp.RequestId)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	err = s.writeActionResult(ctx, tx, req.Output.OutputId, "", txs, sp.RequestId)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite3Store) WriteUnfinishedSafe(ctx context.Context, safe *Safe) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if safe.State != common.RequestStatePending {
		panic(safe.State)
	}
	existed, err := s.checkExistence(ctx, tx, "SELECT address FROM safes WHERE address=?", safe.Address)
	if err != nil || existed {
		return err
	}

	err = s.execOne(ctx, tx, buildInsertionSQL("safes", safeCols), safe.values()...)
	if err != nil {
		return fmt.Errorf("INSERT safes %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) WriteSafeWithRequest(ctx context.Context, safe *Safe, txs []*mtg.Transaction, req *common.Request) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if safe.State != common.RequestStateDone {
		panic(safe.State)
	}
	err = s.execOne(ctx, tx, buildInsertionSQL("safes", safeCols), safe.values()...)
	if err != nil {
		return fmt.Errorf("INSERT safes %v", err)
	}
	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), safe.RequestId)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	err = s.writeActionResult(ctx, tx, req.Output.OutputId, "", txs, safe.RequestId)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite3Store) FinishSafeWithRequest(ctx context.Context, transactionHash, raw string, req *common.Request, safe *Safe, txs []*mtg.Transaction) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if safe.State != common.RequestStatePending {
		panic(safe.State)
	}
	err = s.execOne(ctx, tx, "UPDATE safes SET nonce=?, state=?, updated_at=? WHERE holder=? AND nonce=? AND state=?",
		safe.Nonce+1, common.RequestStateDone, time.Now().UTC(), safe.Holder, safe.Nonce, common.RequestStatePending)
	if err != nil {
		return fmt.Errorf("UPDATE safes %v", err)
	}

	_, err = tx.ExecContext(ctx, "UPDATE signature_requests SET state=?, updated_at=? WHERE transaction_hash=?",
		common.RequestStateDone, req.CreatedAt, transactionHash)
	if err != nil {
		return fmt.Errorf("UPDATE signature_requests %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE transactions SET raw_transaction=?, state=?, updated_at=? WHERE transaction_hash=?",
		raw, common.RequestStateDone, req.CreatedAt, transactionHash)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	err = s.writeActionResult(ctx, tx, req.Output.OutputId, "", txs, req.Id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadSafe(ctx context.Context, holder string) (*Safe, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	return s.readSafe(ctx, tx, holder)
}

func (s *SQLite3Store) ReadSafeByAddress(ctx context.Context, addr string) (*Safe, error) {
	query := fmt.Sprintf("SELECT %s FROM safes WHERE address=?", strings.Join(safeCols, ","))
	row := s.db.QueryRowContext(ctx, query, addr)
	return safeFromRow(row)
}

func (s *SQLite3Store) readSafe(ctx context.Context, tx *sql.Tx, holder string) (*Safe, error) {
	query := fmt.Sprintf("SELECT %s FROM safes WHERE holder=?", strings.Join(safeCols, ","))
	row := tx.QueryRowContext(ctx, query, holder)
	return safeFromRow(row)
}

func (s *SQLite3Store) ListSafesWithState(ctx context.Context, state int) ([]*Safe, error) {
	query := fmt.Sprintf("SELECT %s FROM safes WHERE state=? ORDER BY created_at ASC, request_id ASC", strings.Join(safeCols, ","))
	rows, err := s.db.QueryContext(ctx, query, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var safes []*Safe
	for rows.Next() {
		var s Safe
		var receivers string
		err := rows.Scan(&s.Holder, &s.Chain, &s.Signer, &s.Observer, &s.Timelock, &s.Path, &s.Address, &s.Extra, &receivers, &s.Threshold, &s.RequestId, &s.Nonce, &s.State, &s.SafeAssetId, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			return nil, err
		}
		s.Receivers = strings.Split(receivers, ";")
		safes = append(safes, &s)
	}
	return safes, nil
}
