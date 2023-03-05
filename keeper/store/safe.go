package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/shopspring/decimal"
)

type SafeProposal struct {
	RequestId  string
	Chain      byte
	Holder     string
	Signer     string
	Observer   string
	Timelock   time.Duration
	Accountant string
	Address    string
	Extra      []byte
	Receivers  []string
	Threshold  byte
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type Safe struct {
	Holder     string
	Chain      byte
	Signer     string
	Observer   string
	Timelock   time.Duration
	Accountant string
	Address    string
	Extra      []byte
	Receivers  []string
	Threshold  byte
	RequestId  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

var safeCols = []string{"holder", "chain", "signer", "observer", "timelock", "accountant", "address", "extra", "receivers", "threshold", "request_id", "created_at", "updated_at"}

var safeProposalCols = []string{"request_id", "chain", "holder", "signer", "observer", "timelock", "accountant", "address", "extra", "receivers", "threshold", "created_at", "updated_at"}

func (s *Safe) values() []any {
	return []any{s.Holder, s.Chain, s.Signer, s.Observer, s.Timelock, s.Accountant, s.Address, s.Extra, strings.Join(s.Receivers, ";"), s.Threshold, s.RequestId, s.CreatedAt, s.UpdatedAt}
}

func (s *SafeProposal) values() []any {
	return []any{s.RequestId, s.Chain, s.Holder, s.Signer, s.Observer, s.Timelock, s.Accountant, s.Address, s.Extra, strings.Join(s.Receivers, ";"), s.Threshold, s.CreatedAt, s.UpdatedAt}
}

func safeFromRow(row *sql.Row) (*Safe, error) {
	var s Safe
	var receivers string
	err := row.Scan(&s.Holder, &s.Chain, &s.Signer, &s.Observer, &s.Timelock, &s.Accountant, &s.Address, &s.Extra, &receivers, &s.Threshold, &s.RequestId, &s.CreatedAt, &s.UpdatedAt)
	s.Receivers = strings.Split(receivers, ";")
	return &s, err
}

func safeProposalFromRow(row *sql.Row) (*SafeProposal, error) {
	var s SafeProposal
	var receivers string
	err := row.Scan(&s.RequestId, &s.Chain, &s.Holder, &s.Signer, &s.Observer, &s.Timelock, &s.Accountant, &s.Address, &s.Extra, &receivers, &s.Threshold, &s.CreatedAt, &s.UpdatedAt)
	s.Receivers = strings.Split(receivers, ";")
	return &s, err
}

func (s *SQLite3Store) ReadSafeProposal(ctx context.Context, requestId string) (*SafeProposal, error) {
	query := fmt.Sprintf("SELECT %s FROM safe_proposals WHERE request_id=?", strings.Join(safeProposalCols, ","))
	row := s.db.QueryRowContext(ctx, query, requestId)
	sp, err := safeProposalFromRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return sp, err
}

func (s *SQLite3Store) ReadSafeProposalByAddress(ctx context.Context, addr string) (*SafeProposal, error) {
	query := fmt.Sprintf("SELECT %s FROM safe_proposals WHERE address=?", strings.Join(safeProposalCols, ","))
	row := s.db.QueryRowContext(ctx, query, addr)
	sp, err := safeProposalFromRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return sp, err
}

func (s *SQLite3Store) WriteSafeProposalWithRequest(ctx context.Context, sp *SafeProposal) error {
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
	return tx.Commit()
}

func (s *SQLite3Store) WriteSafeWithRequest(ctx context.Context, safe *Safe, accountantAddress string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	accCols := []string{"holder", "address", "balance", "request_id", "created_at", "updated_at"}
	accVals := []any{safe.Holder, accountantAddress, "0", safe.RequestId, safe.CreatedAt, safe.UpdatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("accountants", accCols), accVals...)
	if err != nil {
		return fmt.Errorf("INSERT accountants %v", err)
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
	safe, err := safeFromRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return safe, err
}

func (s *SQLite3Store) readSafe(ctx context.Context, tx *sql.Tx, holder string) (*Safe, error) {
	query := fmt.Sprintf("SELECT %s FROM safes WHERE holder=?", strings.Join(safeCols, ","))
	row := tx.QueryRowContext(ctx, query, holder)
	safe, err := safeFromRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return safe, err
}

func (s *SQLite3Store) ReadAccountantHolder(ctx context.Context, accountantAddres string) (string, error) {
	query := "SELECT holder FROM accountants WHERE address=?"
	row := s.db.QueryRowContext(ctx, query, accountantAddres)
	err := row.Scan(&accountantAddres)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return accountantAddres, err
}

func (s *SQLite3Store) ReadAccountantBalance(ctx context.Context, holder string) (decimal.Decimal, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return decimal.Zero, err
	}
	defer tx.Rollback()

	return s.readAccountantBalance(ctx, tx, holder)
}

func (s *SQLite3Store) readAccountantBalance(ctx context.Context, tx *sql.Tx, holder string) (decimal.Decimal, error) {
	query := "SELECT balance FROM accountants WHERE holder=?"
	row := tx.QueryRowContext(ctx, query, holder)
	var amount string
	err := row.Scan(&amount)
	if err == sql.ErrNoRows {
		return decimal.Zero, nil
	} else if err != nil {
		return decimal.Zero, err
	}
	balance, err := decimal.NewFromString(amount)
	if err != nil || balance.IsNegative() {
		panic(holder)
	}
	return balance, err
}
