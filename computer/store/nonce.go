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
	Address    string
	Hash       string
	OccupiedBy sql.NullString
	OccupiedAt sql.NullTime
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

var nonceAccountCols = []string{"address", "hash", "occupied_by", "occupied_at", "call_id", "created_at", "updated_at"}

func nonceAccountFromRow(row *sql.Row) (*NonceAccount, error) {
	var a NonceAccount
	err := row.Scan(&a.Address, &a.Hash, &a.OccupiedBy, &a.OccupiedAt, &a.CreatedAt, &a.UpdatedAt)
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

func (s *SQLite3Store) WriteOrUpdateNonceAccount(ctx context.Context, req *Request, address, hash string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.writeOrUpdateNonceAccount(ctx, tx, req, address, hash)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) writeOrUpdateNonceAccount(ctx context.Context, tx *sql.Tx, req *Request, address, hash string) error {
	existed, err := s.checkExistence(ctx, tx, "SELECT address FROM nonce_accounts WHERE address=?", address)
	if err != nil {
		return fmt.Errorf("store.writeOrUpdateNonceAccount(%s) => %v", address, err)
	}

	if existed {
		err = s.execOne(ctx, tx, "UPDATE nonce_accounts SET hash=?, updated_at=? WHERE address=?",
			hash, req.CreatedAt, address)
		if err != nil {
			return fmt.Errorf("UPDATE nonce_accounts %v", err)
		}
	} else {
		vals := []any{address, hash, nil, nil, req.CreatedAt, req.CreatedAt}
		err = s.execOne(ctx, tx, buildInsertionSQL("nonce_accounts", nonceAccountCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT nonce_accounts %v", err)
		}
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}
	return nil
}

func (s *SQLite3Store) assignNonceAccountToUser(ctx context.Context, tx *sql.Tx, req *Request, uid string) (string, error) {
	existed, err := s.checkExistence(ctx, tx, "SELECT address FROM nonce_accounts WHERE user_id=?", uid)
	if err != nil || existed {
		return "", fmt.Errorf("store.checkExistenceFromNonceAccounts(%s) => %t %v", uid, existed, err)
	}

	account, err := readSpareNonceAccount(ctx, tx)
	if err != nil || account == "" {
		return "", fmt.Errorf("store.readSpareNonceAccount() => %s %v", account, err)
	}

	err = s.execOne(ctx, tx, "UPDATE nonce_accounts SET user_id=?, updated_at=? WHERE address=? AND user_id IS NULL AND call_id IS NULL",
		uid, req.CreatedAt, account)
	if err != nil {
		return "", fmt.Errorf("UPDATE nonce_accounts %v", err)
	}

	return account, nil
}

func (s *SQLite3Store) ReadNonceAccount(ctx context.Context, address string) (*NonceAccount, error) {
	query := fmt.Sprintf("SELECT %s FROM nonce_accounts WHERE address=?", strings.Join(nonceAccountCols, ","))
	row := s.db.QueryRowContext(ctx, query, address)

	return nonceAccountFromRow(row)
}

func (s *SQLite3Store) ReadSpareNonceAccount(ctx context.Context) (*NonceAccount, error) {
	query := fmt.Sprintf("SELECT %s FROM nonce_accounts WHERE user_id IS NULL AND call_id IS NULL ORDER BY created_at ASC LIMIT 1", strings.Join(nonceAccountCols, ","))
	row := s.db.QueryRowContext(ctx, query)

	return nonceAccountFromRow(row)
}

func readSpareNonceAccount(ctx context.Context, tx *sql.Tx) (string, error) {
	var account string
	query := "SELECT address FROM nonce_accounts WHERE user_id IS NULL AND call_id IS NULL ORDER BY created_at ASC LIMIT 1"
	row := tx.QueryRowContext(ctx, query)
	err := row.Scan(&account)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return account, err
}

func (s *SQLite3Store) CountSpareNonceAccounts(ctx context.Context) (int, error) {
	query := "SELECT COUNT(*) FROM nonce_accounts WHERE user_id IS NULL AND call_id IS NULL"
	row := s.db.QueryRowContext(ctx, query)

	var count int
	err := row.Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}
