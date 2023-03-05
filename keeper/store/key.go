package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
)

type Key struct {
	Public    string
	Curve     byte
	RequestId string
	Role      byte
	Holder    sql.NullString
	CreatedAt time.Time
	UpdatedAt time.Time
}

var keyCols = []string{"public_key", "curve", "request_id", "role", "holder", "created_at", "updated_at"}

func keyValsFromRequest(r *common.Request, role int) []any {
	return []any{r.Holder, r.Curve, r.Id, role, sql.NullString{}, r.CreatedAt, r.CreatedAt}
}

func (s *SQLite3Store) ReadKey(ctx context.Context, public string) (*Key, error) {
	query := fmt.Sprintf("SELECT %s FROM keys WHERE public_key=?", strings.Join(keyCols, ","))
	row := s.db.QueryRowContext(ctx, query, public)

	var k Key
	err := row.Scan(&k.Public, &k.Curve, &k.RequestId, &k.Role, &k.Holder, &k.CreatedAt, &k.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &k, err
}

func (s *SQLite3Store) CountSpareKeys(ctx context.Context, curve byte, role int) (int, error) {
	query := "SELECT COUNT(*) FROM keys WHERE role=? AND holder IS NULL"
	row := s.db.QueryRowContext(ctx, query, role)

	var count int
	err := row.Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

func (s *SQLite3Store) WriteKeyFromRequest(ctx context.Context, req *common.Request, role int) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.execOne(ctx, tx, buildInsertionSQL("keys", keyCols), keyValsFromRequest(req, role)...)
	if err != nil {
		return fmt.Errorf("INSERT keys %v", err)
	}
	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) AssignSignerAndObserverToHolder(ctx context.Context, req *common.Request) (string, string, string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", "", err
	}
	defer tx.Rollback()

	signer, err := readKeyWithRoleAndHolder(ctx, tx, req.Holder, common.RequestRoleSigner)
	if err != nil {
		return "", "", "", err
	}
	observer, err := readKeyWithRoleAndHolder(ctx, tx, req.Holder, common.RequestRoleObserver)
	if err != nil {
		return "", "", "", err
	}
	accountant, err := readKeyWithRoleAndHolder(ctx, tx, req.Holder, common.RequestRoleAccountant)
	if err != nil {
		return "", "", "", err
	}
	if signer != "" && observer != "" && accountant != "" {
		return signer, observer, accountant, nil
	}
	if signer != "" || observer != "" || accountant != "" {
		panic(req.Holder)
	}

	signer, err = readKeyWithRole(ctx, tx, common.RequestRoleSigner)
	if err != nil {
		return "", "", "", err
	}
	observer, err = readKeyWithRole(ctx, tx, common.RequestRoleObserver)
	if err != nil {
		return "", "", "", err
	}
	accountant, err = readKeyWithRole(ctx, tx, common.RequestRoleAccountant)
	if err != nil {
		return "", "", "", err
	}
	if signer == "" || observer == "" || accountant == "" {
		return "", "", "", nil
	}

	err = s.execOne(ctx, tx, "UPDATE keys SET holder=?, updated_at=? WHERE public_key=? AND holder IS NULL AND role=?",
		req.Holder, req.CreatedAt, signer, common.RequestRoleSigner)
	if err != nil {
		return "", "", "", fmt.Errorf("UPDATE keys %v", err)
	}
	err = s.execOne(ctx, tx, "UPDATE keys SET holder=?, updated_at=? WHERE public_key=? AND holder IS NULL AND role=?",
		req.Holder, req.CreatedAt, observer, common.RequestRoleObserver)
	if err != nil {
		return "", "", "", fmt.Errorf("UPDATE keys %v", err)
	}
	err = s.execOne(ctx, tx, "UPDATE keys SET holder=?, updated_at=? WHERE public_key=? AND holder IS NULL AND role=?",
		req.Holder, req.CreatedAt, accountant, common.RequestRoleAccountant)
	if err != nil {
		return "", "", "", fmt.Errorf("UPDATE keys %v", err)
	}

	return signer, observer, accountant, tx.Commit()
}

func readKeyWithRoleAndHolder(ctx context.Context, tx *sql.Tx, holder string, role int) (string, error) {
	var public string
	row := tx.QueryRowContext(ctx, "SELECT public_key FROM keys WHERE holder=? AND role=?", holder, role)
	err := row.Scan(&public)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return public, err
}

func readKeyWithRole(ctx context.Context, tx *sql.Tx, role int) (string, error) {
	var public string
	row := tx.QueryRowContext(ctx, "SELECT public_key FROM keys WHERE holder IS NULL AND role=? ORDER BY created_at ASC, public_key ASC LIMIT 1", role)
	err := row.Scan(&public)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return public, err
}
