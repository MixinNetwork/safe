package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/gagliardetto/solana-go"
)

type NonceAccount struct {
	Address   string
	Hash      string
	Mix       sql.NullString
	CallId    sql.NullString
	CreatedAt time.Time
	UpdatedAt time.Time
}

var nonceAccountCols = []string{"address", "hash", "mix", "call_id", "call_id", "created_at", "updated_at"}

func nonceAccountFromRow(row Row) (*NonceAccount, error) {
	var a NonceAccount
	err := row.Scan(&a.Address, &a.Hash, &a.Mix, &a.CallId, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (a *NonceAccount) Account() solanaApp.NonceAccount {
	return solanaApp.NonceAccount{
		Address: solana.MustPublicKeyFromBase58(a.Address),
		Hash:    solana.MustHashFromBase58(a.Hash),
	}
}

func (s *SQLite3Store) WriteOrUpdateNonceAccount(ctx context.Context, address, hash string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.writeOrUpdateNonceAccount(ctx, tx, address, hash)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) writeOrUpdateNonceAccount(ctx context.Context, tx *sql.Tx, address, hash string) error {
	existed, err := s.checkExistence(ctx, tx, "SELECT address FROM nonce_accounts WHERE address=?", address)
	if err != nil {
		return fmt.Errorf("store.writeOrUpdateNonceAccount(%s) => %v", address, err)
	}

	now := time.Now().UTC()
	if existed {
		err = s.execOne(ctx, tx, "UPDATE nonce_accounts SET hash=?, updated_at=? WHERE address=?",
			hash, now, address)
		if err != nil {
			return fmt.Errorf("UPDATE nonce_accounts %v", err)
		}
	} else {
		vals := []any{address, hash, nil, nil, now, now}
		err = s.execOne(ctx, tx, buildInsertionSQL("nonce_accounts", nonceAccountCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT nonce_accounts %v", err)
		}
	}

	return nil
}

func (s *SQLite3Store) LockNonceAccountWithMix(ctx context.Context, address, mix string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.execOne(ctx, tx, "UPDATE nonce_accounts SET mix=?, updated_at=? WHERE address=? AND mix IS NULL AND call_id IS NULL",
		mix, address)
	if err != nil {
		return fmt.Errorf("UPDATE nonce_accounts %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) OccupyNonceAccountByCall(ctx context.Context, address, call string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.execOne(ctx, tx, "UPDATE nonce_accounts SET call_id=?, updated_at=? WHERE address=? AND mix IS NOT NULL AND call_id IS NULL",
		call, address)
	if err != nil {
		return fmt.Errorf("UPDATE nonce_accounts %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReleaseLockedNonceAccount(ctx context.Context, address string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.execOne(ctx, tx, "UPDATE nonce_accounts SET mix=?, updated_at=? WHERE address=? AND mix IS NOT NULL AND call_id IS NULL",
		nil, address)
	if err != nil {
		return fmt.Errorf("UPDATE nonce_accounts %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ListLockedNonceAccounts(ctx context.Context) ([]*NonceAccount, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sql := fmt.Sprintf("SELECT %s FROM nonce_accounts WHERE mix IS NOT NULL AND call_id IS NULL ORDER BY updated_at ASC LIMIT 100", strings.Join(nonceAccountCols, ","))
	rows, err := s.db.QueryContext(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var as []*NonceAccount
	for rows.Next() {
		nonce, err := nonceAccountFromRow(rows)
		if err != nil {
			return nil, err
		}
		as = append(as, nonce)
	}
	return as, nil
}

func (s *SQLite3Store) ReadNonceAccount(ctx context.Context, address string) (*NonceAccount, error) {
	query := fmt.Sprintf("SELECT %s FROM nonce_accounts WHERE address=?", strings.Join(nonceAccountCols, ","))
	row := s.db.QueryRowContext(ctx, query, address)

	return nonceAccountFromRow(row)
}

func (s *SQLite3Store) ReadSpareNonceAccount(ctx context.Context) (*NonceAccount, error) {
	query := fmt.Sprintf("SELECT %s FROM nonce_accounts WHERE mix IS NULL AND call_id IS NULL ORDER BY created_at ASC LIMIT 1", strings.Join(nonceAccountCols, ","))
	row := s.db.QueryRowContext(ctx, query)

	return nonceAccountFromRow(row)
}

func (s *SQLite3Store) CountNonceAccounts(ctx context.Context) (int, error) {
	query := "SELECT COUNT(*) FROM nonce_accounts"
	row := s.db.QueryRowContext(ctx, query)

	var count int
	err := row.Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}
