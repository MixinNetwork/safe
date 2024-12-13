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

var startUserId = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(48), nil)

type User struct {
	UserId    string
	RequestId string
	Address   string
	Public    string
	CreatedAt time.Time
}

var userCols = []string{"user_id", "request_id", "address", "public", "created_at"}

func userFromRow(row *sql.Row) (*User, error) {
	var u User
	err := row.Scan(&u.UserId, &u.RequestId, &u.Address, &u.Public, &u.CreatedAt)
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

func (s *SQLite3Store) GetNextUserId(ctx context.Context) (*big.Int, error) {
	u, err := s.ReadLatestUser(ctx)
	if err != nil {
		return nil, err
	}
	id := startUserId
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

	vals := []any{id.String(), req.Id, address, key, time.Now()}
	err = s.execOne(ctx, tx, buildInsertionSQL("users", userCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT users %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?", common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}
	err = s.writeActionResult(ctx, tx, req.Output.OutputId, nil, "", req.Id)
	if err != nil {
		return err
	}

	return tx.Commit()
}
