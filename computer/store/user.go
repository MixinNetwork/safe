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

var StartUserId = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(48), nil)
var DefaultPath = []byte{0, 0, 0, 0, 0, 0, 0, 0}

// Public is the underived key with defaultPath controled by mpc
type User struct {
	UserId       string
	RequestId    string
	MixAddress   string
	ChainAddress string
	Public       string
	NonceAccount string
	CreatedAt    time.Time
}

var userCols = []string{"user_id", "request_id", "mix_address", "chain_address", "public", "nonce_account", "created_at"}

func userFromRow(row *sql.Row) (*User, error) {
	var u User
	err := row.Scan(&u.UserId, &u.RequestId, &u.MixAddress, &u.ChainAddress, &u.Public, &u.NonceAccount, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &u, err
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
	query := fmt.Sprintf("SELECT %s FROM users WHERE user_id!='10000' ORDER BY created_at DESC LIMIT 1", strings.Join(userCols, ","))
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

func (s *SQLite3Store) WriteUserWithRequest(ctx context.Context, req *Request, id, mixAddress, chainAddress, key string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	account, err := s.assignNonceAccountToUser(ctx, tx, req, id)
	if err != nil {
		return err
	}

	vals := []any{id, req.Id, mixAddress, chainAddress, key, account, time.Now().UTC()}
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
