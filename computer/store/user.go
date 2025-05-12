package store

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
)

var (
	StartUserId = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(48), nil)
	DefaultPath = []byte{0, 0, 0, 0, 0, 0, 0, 0}
)

type User struct {
	UserId       string
	RequestId    string
	MixAddress   string
	ChainAddress string
	Public       string // public is the master with defaultPath controlled by mpc
	CreatedAt    time.Time
}

var userCols = []string{"user_id", "request_id", "mix_address", "chain_address", "public", "created_at"}

func userFromRow(row Row) (*User, error) {
	var u User
	err := row.Scan(&u.UserId, &u.RequestId, &u.MixAddress, &u.ChainAddress, &u.Public, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &u, err
}

func (u *User) Id() *big.Int {
	b, ok := new(big.Int).SetString(u.UserId, 10)
	if !ok || b.Sign() <= 0 {
		panic(u.UserId)
	}
	if b.Cmp(StartUserId) < 0 {
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

func (u *User) FingerprintWithEmptyPath() []byte {
	fp := common.Fingerprint(u.Public)
	fp = append(fp, DefaultPath...)
	return fp
}

func (u *User) FingerprintWithPath() []byte {
	fp := common.Fingerprint(u.Public)
	fp = append(fp, u.IdBytes()...)
	return fp
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
	query := fmt.Sprintf("SELECT %s FROM users ORDER BY created_at DESC LIMIT 1", strings.Join(userCols, ","))
	row := s.db.QueryRowContext(ctx, query)

	return userFromRow(row)
}

func (s *SQLite3Store) ReadUser(ctx context.Context, id *big.Int) (*User, error) {
	query := fmt.Sprintf("SELECT %s FROM users WHERE user_id=?", strings.Join(userCols, ","))
	row := s.db.QueryRowContext(ctx, query, id.String())

	return userFromRow(row)
}

func (s *SQLite3Store) ReadUserByMixAddress(ctx context.Context, address string) (*User, error) {
	query := fmt.Sprintf("SELECT %s FROM users WHERE mix_address=?", strings.Join(userCols, ","))
	row := s.db.QueryRowContext(ctx, query, address)

	return userFromRow(row)
}

func (s *SQLite3Store) ReadUserByChainAddress(ctx context.Context, address string) (*User, error) {
	query := fmt.Sprintf("SELECT %s FROM users WHERE chain_address=?", strings.Join(userCols, ","))
	row := s.db.QueryRowContext(ctx, query, address)

	return userFromRow(row)
}

func (s *SQLite3Store) WriteUserWithRequest(ctx context.Context, req *Request, id, mixAddress, chainAddress, master string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	vals := []any{id, req.Id, mixAddress, chainAddress, master, time.Now().UTC()}
	err = s.execOne(ctx, tx, buildInsertionSQL("users", userCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT users %v", err)
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) CountUsers(ctx context.Context) (int, error) {
	query := "SELECT COUNT(*) FROM users"
	row := s.db.QueryRowContext(ctx, query)

	var count int
	err := row.Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

func (s *SQLite3Store) CheckInternalAccounts(ctx context.Context, accounts []string) (int, error) {
	placeholders := strings.Repeat("?, ", len(accounts))
	placeholders = strings.TrimSuffix(placeholders, ", ")

	args := make([]any, len(accounts))
	for i, addr := range accounts {
		args[i] = addr
	}

	query := fmt.Sprintf("SELECT COUNT(1) FROM users WHERE chain_address IN (%s)", placeholders)
	row := s.db.QueryRowContext(ctx, query, args...)

	var count int
	err := row.Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

func (s *SQLite3Store) ListNewUsersAfter(ctx context.Context, offset time.Time) ([]*User, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sql := fmt.Sprintf("SELECT %s FROM users WHERE created_at>? ORDER BY created_at ASC LIMIT 100", strings.Join(userCols, ","))
	rows, err := s.db.QueryContext(ctx, sql, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var us []*User
	for rows.Next() {
		call, err := userFromRow(rows)
		if err != nil {
			return nil, err
		}
		us = append(us, call)
	}
	return us, nil
}
