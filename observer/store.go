package observer

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
)

type Asset struct {
	AssetId   string
	MixinId   string
	AssetKey  string
	Symbol    string
	Name      string
	Decimals  uint32
	Chain     byte
	CreatedAt time.Time
}

type Deposit struct {
	TransactionHash string
	OutputIndex     int64
	AssetId         string
	Amount          string
	Receiver        string
	State           int
	Chain           byte
	Holder          string
	Category        byte
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Transaction struct {
	TransactionHash string
	RawTransaction  string
	Chain           byte
	Holder          string
	Signer          string
	Accountant      string
	Signature       string
	State           byte
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

var assetCols = []string{"asset_id", "mixin_id", "asset_key", "symbol", "name", "decimals", "chain", "created_at"}

var depositsCols = []string{"transaction_hash", "output_index", "asset_id", "amount", "receiver", "state", "chain", "holder", "category", "created_at", "updated_at"}

func (d *Deposit) values() []any {
	return []any{d.TransactionHash, d.OutputIndex, d.AssetId, d.Amount, d.Receiver, d.State, d.Chain, d.Holder, d.Category, d.CreatedAt, d.UpdatedAt}
}

var transactionCols = []string{"transaction_hash", "raw_transaction", "chain", "holder", "signer", "accountant", "signature", "state", "created_at", "updated_at"}

func (t *Transaction) values() []any {
	return []any{t.TransactionHash, t.RawTransaction, t.Chain, t.Holder, t.Signer, t.Accountant, t.Signature, t.State, t.CreatedAt, t.UpdatedAt}
}

func (t *Transaction) Signers() []string {
	switch t.State {
	case common.RequestStateInitial:
		return []string{}
	case common.RequestStatePending:
		return []string{"holder"}
	case common.RequestStateDone:
		return []string{"holder", "signer"}
	}
	panic(t.State)
}

func (s *SQLite3Store) WriteAccountProposalIfNotExists(ctx context.Context, address string, createdAt time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existed, err := s.checkExistence(ctx, tx, "SELECT created_at FROM accounts WHERE address=?", address)
	if err != nil || existed {
		return err
	}

	err = s.execOne(ctx, tx, buildInsertionSQL("accounts", []string{"address", "created_at"}), address, createdAt)
	if err != nil {
		return fmt.Errorf("INSERT accounts %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) CheckAccountProposed(ctx context.Context, addr string) (bool, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT created_at FROM accounts WHERE address=?", addr)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	return rows.Next(), nil
}

func (s *SQLite3Store) ListPendingDeposits(ctx context.Context, chain int) ([]*Deposit, error) {
	query := fmt.Sprintf("SELECT %s FROM deposits WHERE chain=? AND state=? ORDER BY created_at ASC", strings.Join(depositsCols, ","))
	rows, err := s.db.QueryContext(ctx, query, chain, common.RequestStateInitial)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deposits []*Deposit
	for rows.Next() {
		var d Deposit
		err := rows.Scan(&d.TransactionHash, &d.OutputIndex, &d.AssetId, &d.Amount, &d.Receiver, &d.State, &d.Chain, &d.Holder, &d.Category, &d.CreatedAt, &d.UpdatedAt)
		if err != nil {
			return nil, err
		}
		deposits = append(deposits, &d)
	}
	return deposits, nil
}

func (s *SQLite3Store) WritePendingDepositIfNotExists(ctx context.Context, d *Deposit) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if d.State != common.RequestStateInitial {
		panic(d.State)
	}

	existed, err := s.checkExistence(ctx, tx, "SELECT amount FROM deposits WHERE transaction_hash=? AND output_index=?", d.TransactionHash, d.OutputIndex)
	if err != nil || existed {
		return err
	}

	err = s.execOne(ctx, tx, buildInsertionSQL("deposits", depositsCols), d.values()...)
	if err != nil {
		return fmt.Errorf("INSERT deposits %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ConfirmPendingDeposit(ctx context.Context, transactionHash string, outputIndex int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	query := "UPDATE deposits SET state=?, updated_at=? WHERE transaction_hash=? AND output_index=? AND state=?"
	err = s.execOne(ctx, tx, query, common.RequestStateDone, time.Now().UTC(), transactionHash, outputIndex, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE deposits %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ListPendingTransactionApprovals(ctx context.Context, chain byte) ([]*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions WHERE chain=? AND state=? ORDER BY created_at ASC", strings.Join(transactionCols, ","))
	rows, err := s.db.QueryContext(ctx, query, chain, common.RequestStatePending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var approvals []*Transaction
	for rows.Next() {
		var t Transaction
		err = rows.Scan(&t.TransactionHash, &t.RawTransaction, &t.Chain, &t.Holder, &t.Signer, &t.Accountant, &t.Signature, &t.State, &t.CreatedAt, &t.UpdatedAt)
		if err != nil {
			return nil, err
		}
		approvals = append(approvals, &t)
	}
	return approvals, nil
}

func (s *SQLite3Store) WriteTransactionApprovalIfNotExists(ctx context.Context, approval *Transaction) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existed, err := s.checkExistence(ctx, tx, "SELECT raw_transaction FROM transactions WHERE transaction_hash=?", approval.TransactionHash)
	if err != nil || existed {
		return err
	}

	err = s.execOne(ctx, tx, buildInsertionSQL("transactions", transactionCols), approval.values()...)
	if err != nil {
		return fmt.Errorf("INSERT transactions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) AddTransactionPartials(ctx context.Context, transactionHash string, raw, sigBase64 string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.execOne(ctx, tx, "UPDATE transactions SET raw_transaction=?, signature=?, state=?, updated_at=? WHERE transaction_hash=? AND state=?",
		raw, sigBase64, common.RequestStatePending, time.Now().UTC(), transactionHash, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) UpdateTransactionApprovalRequestTime(ctx context.Context, transactionHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.execOne(ctx, tx, "UPDATE transactions SET updated_at=? WHERE transaction_hash=? AND state=?",
		time.Now().UTC(), transactionHash, common.RequestStatePending)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) FinishTransactionSignatures(ctx context.Context, transactionHash string, raw string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.execOne(ctx, tx, "UPDATE transactions SET raw_transaction=?, state=?, updated_at=? WHERE transaction_hash=?",
		raw, common.RequestStateDone, time.Now().UTC(), transactionHash)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadTransactionApproval(ctx context.Context, hash string) (*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions WHERE transaction_hash=?", strings.Join(transactionCols, ","))
	row := s.db.QueryRowContext(ctx, query, hash)

	var t Transaction
	err := row.Scan(&t.TransactionHash, &t.RawTransaction, &t.Chain, &t.Holder, &t.Signer, &t.Accountant, &t.Signature, &t.State, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &t, err
}

func (s *SQLite3Store) WriteAccountantKey(ctx context.Context, chain byte, pub, priv string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cols := []string{"public_key", "private_key", "chain", "created_at"}
	vals := []any{pub, priv, chain, time.Now().UTC()}
	err = s.execOne(ctx, tx, buildInsertionSQL("accountants", cols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT accountants %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadAccountantKey(ctx context.Context, pub string, chain byte) (string, error) {
	var private string
	row := s.db.QueryRowContext(ctx, "SELECT private_key FROM accountants WHERE public_key=? AND chain=?", pub, chain)
	err := row.Scan(&private)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return private, err
}

func (s *SQLite3Store) WriteObserverKeys(ctx context.Context, chain byte, publics []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, pub := range publics {
		cols := []string{"public_key", "chain", "created_at"}
		vals := []any{pub, chain, time.Now().UTC()}
		err = s.execOne(ctx, tx, buildInsertionSQL("observers", cols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT observers %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadObserverKey(ctx context.Context, chain byte) (string, error) {
	var public string
	row := s.db.QueryRowContext(ctx, "SELECT public_key FROM observers WHERE chain=? LIMIT 1", chain)
	err := row.Scan(&public)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return public, err
}

func (s *SQLite3Store) DeleteObserverKey(ctx context.Context, pub string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.execOne(ctx, tx, "DELETE FROM observers WHERE public_key=?", pub)
	if err != nil {
		return fmt.Errorf("DELETE observers %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadAssetMeta(ctx context.Context, id string) (*Asset, error) {
	query := fmt.Sprintf("SELECT %s FROM assets WHERE asset_id=? OR mixin_id=?", strings.Join(assetCols, ","))
	row := s.db.QueryRowContext(ctx, query, id, id)

	var a Asset
	err := row.Scan(&a.AssetId, &a.MixinId, &a.AssetKey, &a.Symbol, &a.Name, &a.Decimals, &a.Chain, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *SQLite3Store) WriteAssetMeta(ctx context.Context, asset *Asset) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	vals := []any{asset.AssetId, asset.MixinId, asset.AssetKey, asset.Symbol, asset.Name, asset.Decimals, asset.Chain, asset.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("assets", assetCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT assets %v", err)
	}
	return tx.Commit()
}
