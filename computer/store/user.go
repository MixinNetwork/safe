package store

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"strings"
	"time"

	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/gagliardetto/solana-go"
)

var StartUserId = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(48), nil)
var MPCUserId = big.NewInt(10000)

type User struct {
	UserId       string
	RequestId    string
	Address      string
	Public       string
	NonceAccount string
	CreatedAt    time.Time
}

type NonceAccount struct {
	Address   string
	Hash      string
	UserId    sql.NullString
	CreatedAt time.Time
	UpdatedAt time.Time
}

var userCols = []string{"user_id", "request_id", "address", "public", "nonce_account", "created_at"}

var nonceAccountCols = []string{"address", "hash", "user_id", "created_at", "updated_at"}

func userFromRow(row *sql.Row) (*User, error) {
	var u User
	err := row.Scan(&u.UserId, &u.RequestId, &u.Address, &u.Public, &u.NonceAccount, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &u, err
}

func nonceAccountFromRow(row *sql.Row) (*NonceAccount, error) {
	var a NonceAccount
	err := row.Scan(&a.Address, &a.Hash, &a.UserId, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &a, err
}

func (u *User) Id() *big.Int {
	b, ok := new(big.Int).SetString(u.UserId, 10)
	if !ok || b.Sign() < 0 {
		panic(u.UserId)
	}
	return b
}

func (u *User) IdBytes() []byte {
	bid := u.Id()
	data := make([]byte, 8)
	data = bid.FillBytes(data)
	return data
}

func (a *NonceAccount) Account() solanaApp.NonceAccount {
	return solanaApp.NonceAccount{
		Address: solana.MustPublicKeyFromBase58(a.Address),
		Hash:    solana.MustHashFromBase58(a.Hash),
	}
}

func (s *SQLite3Store) GetNextUserId(ctx context.Context) (*big.Int, error) {
	u, err := s.ReadLatestUser(ctx)
	if err != nil {
		return nil, err
	}
	id := StartUserId
	if u != nil {
		id = u.Id()
	}
	id = big.NewInt(0).Add(id, big.NewInt(1))
	return id, nil
}

func (s *SQLite3Store) ReadLatestUser(ctx context.Context) (*User, error) {
	query := fmt.Sprintf("SELECT %s FROM users WHERE user_id!='10000' ORDER BY created_at DESC LIMIT 1", strings.Join(userCols, ","))
	row := s.db.QueryRowContext(ctx, query)

	return userFromRow(row)
}

func (s *SQLite3Store) ReadUser(ctx context.Context, id *big.Int) (*User, error) {
	query := fmt.Sprintf("SELECT %s FROM users WHERE user_id=?", strings.Join(userCols, ","))
	row := s.db.QueryRowContext(ctx, query, id.String())

	return userFromRow(row)
}

func (s *SQLite3Store) ReadUserByAddress(ctx context.Context, address string) (*User, error) {
	query := fmt.Sprintf("SELECT %s FROM users WHERE address=?", strings.Join(userCols, ","))
	row := s.db.QueryRowContext(ctx, query, address)

	return userFromRow(row)
}

func (s *SQLite3Store) WriteUserWithRequest(ctx context.Context, req *Request, address string) error {
	id, err := s.GetNextUserId(ctx)
	if err != nil {
		return err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	key, err := s.assignKeyToUser(ctx, tx, req, id.String())
	if err != nil {
		return err
	}
	account, err := s.assignNonceAccountToUser(ctx, tx, req, id.String())
	if err != nil {
		return err
	}

	vals := []any{id.String(), req.Id, address, key, account, time.Now()}
	err = s.execOne(ctx, tx, buildInsertionSQL("users", userCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT users %v", err)
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

func (s *SQLite3Store) WriteSignerUserWithRequest(ctx context.Context, req *Request, address, key string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.execOne(ctx, tx, "UPDATE keys SET user_id=?, updated_at=? WHERE public=? AND user_id IS NULL",
		MPCUserId.String(), req.CreatedAt, key)
	if err != nil {
		return fmt.Errorf("UPDATE keys %v", err)
	}

	vals := []any{MPCUserId.String(), req.Id, address, key, "", time.Now()}
	err = s.execOne(ctx, tx, buildInsertionSQL("users", userCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT users %v", err)
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
		vals := []any{address, hash, nil, req.CreatedAt, req.CreatedAt}
		err = s.execOne(ctx, tx, buildInsertionSQL("nonce_accounts", nonceAccountCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT nonce_accounts %v", err)
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

	err = s.execOne(ctx, tx, "UPDATE nonce_accounts SET user_id=?, updated_at=? WHERE address=? AND user_id IS NULL",
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

func readSpareNonceAccount(ctx context.Context, tx *sql.Tx) (string, error) {
	var account string
	query := "SELECT address FROM nonce_accounts WHERE user_id IS NULL ORDER BY created_at ASC LIMIT 1"
	row := tx.QueryRowContext(ctx, query)
	err := row.Scan(&account)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return account, err
}

func (s *SQLite3Store) CountSpareNonceAccounts(ctx context.Context) (int, error) {
	query := "SELECT COUNT(*) FROM nonce_accounts WHERE user_id IS NULL"
	row := s.db.QueryRowContext(ctx, query)

	var count int
	err := row.Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}
