package store

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/common"
)

func (s *SQLite3Store) TestWriteKey(ctx context.Context, id, public string, conf []byte, saved bool) error {
	if !common.CheckTestEnvironment(ctx) {
		return fmt.Errorf("invalid env")
	}

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
	cols := []string{"public", "fingerprint", "share", "session_id", "user_id", "created_at", "updated_at", "confirmed_at"}
	values := []any{public, fingerprint, share, id, nil, timestamp, timestamp, timestamp}
	if saved {
		cols = append(cols, "backed_up_at")
		values = append(values, timestamp)
	}

	err = s.execOne(ctx, tx, buildInsertionSQL("keys", cols), values...)
	if err != nil {
		return fmt.Errorf("SQLite3Store INSERT keys %v", err)
	}

	return tx.Commit()
}
