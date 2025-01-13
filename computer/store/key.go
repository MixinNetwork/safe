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

const (
	KeygenRequestTimeKey             = "keygen-request-time"
	NonceAccountRequestTimeKey       = "nonce-request-time"
	WithdrawalConfirmRequestSequence = "withdrawal-request-sequence"
	BlockScanHeight                  = "block-scan-height"
)

type KeygenResult struct {
	Public []byte
	Share  []byte
	SSID   []byte
}

type Key struct {
	Public      string
	Fingerprint string
	Share       string
	SessionId   string
	UserId      sql.NullString
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ConfirmedAt sql.NullTime
	BackedUpAt  sql.NullTime
}

func (s *SQLite3Store) WriteKeyIfNotExists(ctx context.Context, session *Session, public string, conf []byte, saved bool) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT public FROM keys WHERE public=?", public)
	if err != nil || existed {
		return err
	}

	timestamp := time.Now().UTC()
	share := common.Base91Encode(conf)
	fingerprint := hex.EncodeToString(common.Fingerprint(public))
	cols := []string{"public", "fingerprint", "share", "session_id", "user_id", "created_at", "updated_at"}
	values := []any{public, fingerprint, share, session.Id, nil, session.CreatedAt, timestamp}
	if saved {
		cols = append(cols, "backed_up_at")
		values = append(values, timestamp)
	}

	err = s.execOne(ctx, tx, buildInsertionSQL("keys", cols), values...)
	if err != nil {
		return fmt.Errorf("SQLite3Store INSERT keys %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE sessions SET public=?, state=?, updated_at=? WHERE session_id=? AND created_at=updated_at AND state=?",
		public, common.RequestStatePending, timestamp, session.Id, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE sessions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ListUnbackupedKeys(ctx context.Context, threshold int) ([]*Key, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	cols := []string{"public", "fingerprint", "share", "session_id", "created_at", "updated_at", "backed_up_at"}
	query := fmt.Sprintf("SELECT %s FROM keys WHERE confirmed_at IS NOT NULL AND backed_up_at IS NULL ORDER BY created_at ASC, confirmed_at ASC LIMIT %d", strings.Join(cols, ","), threshold)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*Key
	for rows.Next() {
		var k Key
		err := rows.Scan(&k.Public, &k.Fingerprint, &k.Share, &k.SessionId, &k.CreatedAt, &k.UpdatedAt, &k.BackedUpAt)
		if err != nil {
			return nil, err
		}
		keys = append(keys, &k)
	}
	return keys, nil
}

func (s *SQLite3Store) CountSpareKeys(ctx context.Context) (int, error) {
	query := "SELECT COUNT(*) FROM keys WHERE user_id IS NULL AND confirmed_at IS NOT NULL"
	row := s.db.QueryRowContext(ctx, query)

	var count int
	err := row.Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

func (s *SQLite3Store) GetSpareKey(ctx context.Context) (*Key, error) {
	cols := []string{"public", "fingerprint", "share", "session_id", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM keys WHERE user_id IS NULL AND confirmed_at IS NOT NULL ORDER BY created_at ASC, confirmed_at ASC LIMIT 1", strings.Join(cols, ","))
	row := s.db.QueryRowContext(ctx, query)

	var k Key
	err := row.Scan(&k.Public, &k.Fingerprint, &k.Share, &k.SessionId, &k.CreatedAt, &k.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &k, nil
}

func (s *SQLite3Store) MarkKeyBackuped(ctx context.Context, public string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE keys SET backed_up_at=? WHERE public=? AND backed_up_at IS NULL AND confirmed_at IS NOT NULL"
	err = s.execOne(ctx, tx, query, time.Now().UTC(), public)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE keys %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) MarkKeyComfirmedWithRequest(ctx context.Context, req *Request, public string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE keys SET confirmed_at=?, updated_at=? WHERE public=? AND confirmed_at IS NULL"
	err = s.execOne(ctx, tx, query, req.CreatedAt, req.CreatedAt, public)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE keys %v", err)
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadKeyByFingerprint(ctx context.Context, sum string) (string, []byte, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var public, share string
	row := s.db.QueryRowContext(ctx, "SELECT public, share FROM keys WHERE fingerprint=?", sum)
	err := row.Scan(&public, &share)
	if err == sql.ErrNoRows {
		return "", nil, nil
	} else if err != nil {
		return "", nil, err
	}
	conf, err := common.Base91Decode(share)
	return public, conf, err
}

func (s *SQLite3Store) ReadFirstGeneratedKey(ctx context.Context) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var public string
	row := s.db.QueryRowContext(ctx, "SELECT public FROM keys WHERE user_id IS NULL AND confirmed_at IS NOT NULL ORDER BY created_at ASC, confirmed_at ASC LIMIT 1")
	err := row.Scan(&public)
	if err == sql.ErrNoRows {
		return "", nil
	} else if err != nil {
		return "", err
	}
	return public, err
}

func (s *SQLite3Store) CheckMpcKeyInitialized(ctx context.Context) (bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer common.Rollback(tx)

	return s.checkExistence(ctx, tx, "SELECT public FROM keys WHERE user_id=?", MPCUserId.String())
}

func (s *SQLite3Store) assignKeyToUser(ctx context.Context, tx *sql.Tx, req *Request, uid string) (string, error) {
	existed, err := s.checkExistence(ctx, tx, "SELECT public FROM keys WHERE user_id=? AND confirmed_at IS NOT NULL", uid)
	if err != nil || existed {
		return "", fmt.Errorf("store.checkKeyWithPublic(%s) => %t %v", uid, existed, err)
	}

	key, err := readSpareKey(ctx, tx)
	if err != nil || key == "" {
		return "", fmt.Errorf("store.readSpareKey() => %s %v", key, err)
	}

	err = s.execOne(ctx, tx, "UPDATE keys SET user_id=?, updated_at=? WHERE public=? AND user_id IS NULL AND confirmed_at IS NOT NULL",
		uid, req.CreatedAt, key)
	if err != nil {
		return "", fmt.Errorf("UPDATE keys %v", err)
	}

	return key, nil
}

func readSpareKey(ctx context.Context, tx *sql.Tx) (string, error) {
	var public string
	query := "SELECT public FROM keys WHERE user_id IS NULL AND confirmed_at IS NOT NULL ORDER BY created_at ASC, confirmed_at ASC LIMIT 1"
	row := tx.QueryRowContext(ctx, query)
	err := row.Scan(&public)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return public, err
}
