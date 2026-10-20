package observer

import (
	"context"
	"database/sql"
	"time"

	"github.com/MixinNetwork/safe/common"
)

// Run before either scanner starts so the pending cursor inherits the old cursor once.
func (s *SQLite3Store) migratePendingDepositCheckpoints(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	ethereumExists, err := s.checkExistence(ctx, tx, "SELECT key FROM properties WHERE key=?", pendingDepositCheckpointKey(common.SafeChainEthereum))
	if err != nil {
		return err
	}
	polygonExists, err := s.checkExistence(ctx, tx, "SELECT key FROM properties WHERE key=?", pendingDepositCheckpointKey(common.SafeChainPolygon))
	if err != nil {
		return err
	}
	if ethereumExists && polygonExists {
		return nil
	}

	cols := []string{"key", "value", "created_at", "updated_at"}
	now := time.Now().UTC()
	for _, chain := range []byte{common.SafeChainEthereum, common.SafeChainPolygon} {
		if (chain == common.SafeChainEthereum && ethereumExists) || (chain == common.SafeChainPolygon && polygonExists) {
			continue
		}
		var value string
		err := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", depositCheckpointKey(chain)).Scan(&value)
		if err == sql.ErrNoRows {
			continue
		} else if err != nil {
			return err
		}
		err = s.execOne(ctx, tx, buildInsertionSQL("properties", cols), pendingDepositCheckpointKey(chain), value, now, now)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
