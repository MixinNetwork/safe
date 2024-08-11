package store

import (
	"context"
	"database/sql"
	"encoding/hex"
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
	Extra     string
	Flags     byte
	Holder    sql.NullString
	CreatedAt time.Time
	UpdatedAt time.Time
}

var keyCols = []string{"public_key", "curve", "request_id", "role", "extra", "flags", "holder", "created_at", "updated_at"}

func keyValsFromRequest(r *common.Request, role int, extra []byte, flags byte) []any {
	return []any{r.Holder, r.Curve, r.Id, role, hex.EncodeToString(extra), flags, sql.NullString{}, r.CreatedAt, r.CreatedAt}
}

func (s *SQLite3Store) ReadKey(ctx context.Context, public string) (*Key, error) {
	query := fmt.Sprintf("SELECT %s FROM keys WHERE public_key=?", strings.Join(keyCols, ","))
	row := s.db.QueryRowContext(ctx, query, public)

	var k Key
	err := row.Scan(&k.Public, &k.Curve, &k.RequestId, &k.Role, &k.Extra, &k.Flags, &k.Holder, &k.CreatedAt, &k.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &k, err
}

func (s *SQLite3Store) CountSpareKeys(ctx context.Context, curve, flags byte, role int) (int, error) {
	query := "SELECT COUNT(*) FROM keys WHERE role=? AND curve=? AND flags=? AND holder IS NULL"
	row := s.db.QueryRowContext(ctx, query, role, curve, flags)

	var count int
	err := row.Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

func (s *SQLite3Store) WriteKeyFromRequest(ctx context.Context, req *common.Request, role int, extra []byte, flags byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if common.NormalizeCurve(req.Curve) != req.Curve {
		panic(req.Curve)
	}

	err = s.execOne(ctx, tx, buildInsertionSQL("keys", keyCols), keyValsFromRequest(req, role, extra, flags)...)
	if err != nil {
		return fmt.Errorf("INSERT keys %v", err)
	}
	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	err = s.writeActionResult(ctx, tx, req.Output.OutputId, "", nil, req.Id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) AssignSignerAndObserverToHolder(ctx context.Context, req *common.Request, maturity time.Duration, observerPref string) (string, string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()

	signer, err := readKeyWithRoleAndHolder(ctx, tx, req.Holder, common.RequestRoleSigner)
	if err != nil {
		return "", "", err
	}
	observer, err := readKeyWithRoleAndHolder(ctx, tx, req.Holder, common.RequestRoleObserver)
	if err != nil {
		return "", "", err
	}
	if signer != "" && observer != "" {
		return signer, observer, nil
	}
	if signer != "" || observer != "" {
		panic(req.Holder)
	}

	signer, err = readKeyWithRoleAndCurve(ctx, tx, common.RequestRoleSigner, common.NormalizeCurve(req.Curve), maturity, "")
	if err != nil {
		return "", "", err
	}
	observer, err = readKeyWithRoleAndCurve(ctx, tx, common.RequestRoleObserver, common.NormalizeCurve(req.Curve), maturity, observerPref)
	if err != nil {
		return "", "", err
	}
	if signer == "" || observer == "" {
		return "", "", err
	}

	err = s.execOne(ctx, tx, "UPDATE keys SET holder=?, updated_at=? WHERE public_key=? AND holder IS NULL AND role=? AND curve=?",
		req.Holder, req.CreatedAt, signer, common.RequestRoleSigner, common.NormalizeCurve(req.Curve))
	if err != nil {
		return "", "", fmt.Errorf("UPDATE keys %v", err)
	}
	err = s.execOne(ctx, tx, "UPDATE keys SET holder=?, updated_at=? WHERE public_key=? AND holder IS NULL AND role=? AND curve=?",
		req.Holder, req.CreatedAt, observer, common.RequestRoleObserver, common.NormalizeCurve(req.Curve))
	if err != nil {
		return "", "", fmt.Errorf("UPDATE keys %v", err)
	}

	return signer, observer, tx.Commit()
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

func readKeyWithRoleAndCurve(ctx context.Context, tx *sql.Tx, role int, crv byte, maturity time.Duration, pref string) (string, error) {
	var public string
	query := "SELECT public_key FROM keys WHERE holder IS NULL AND role=? AND curve=? AND flags=? AND created_at<? ORDER BY created_at ASC, public_key ASC LIMIT 1"
	params := []any{role, crv, common.RequestFlagNone, time.Now().Add(-maturity)}
	if pref != "" {
		query = "SELECT public_key FROM keys WHERE holder IS NULL AND role=? AND curve=? AND flags=? AND public_key=? LIMIT 1"
		params = []any{role, crv, common.RequestFlagCustomObserverKey, pref}
	}
	row := tx.QueryRowContext(ctx, query, params...)
	err := row.Scan(&public)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return public, err
}
