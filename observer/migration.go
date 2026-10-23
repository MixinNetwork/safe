package observer

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/common"
)

const depositChangeMigrationKey = "migration-deposits-is-change"

// Migrate prepares observer data before HTTP and background workers start.
func (node *Node) Migrate(ctx context.Context) error {
	if err := node.store.migratePendingDepositCheckpoints(ctx); err != nil {
		return err
	}
	return node.migrateDepositChanges(ctx)
}

func (node *Node) migrateDepositChanges(ctx context.Context) error {
	s := node.store
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	exists, err := s.checkExistence(ctx, tx, "SELECT value FROM properties WHERE key=?", depositChangeMigrationKey)
	if err != nil || exists {
		return err
	}

	_, err = tx.ExecContext(ctx, "ALTER TABLE deposits ADD COLUMN is_change BOOLEAN NOT NULL DEFAULT FALSE")
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS deposits_by_chain_created ON deposits(chain, created_at)")
	if err != nil {
		return err
	}
	// EVM deposits retain the default false value.
	for _, chain := range []byte{common.SafeChainBitcoin, common.SafeChainLitecoin} {
		for offset := int64(0); ; {
			batch, err := s.listDepositsByCreatedAt(ctx, tx, int(chain), "", 0, offset, false)
			if err != nil {
				return err
			}
			sent, err := s.queryDepositSentHashes(ctx, tx, batch)
			if err != nil {
				return err
			}
			for _, d := range batch {
				change := node.bitcoinCheckDepositChange(ctx, d.TransactionHash, d.OutputIndex, sent[d.TransactionHash])
				err := s.execOne(ctx, tx, "UPDATE deposits SET is_change=? WHERE transaction_hash=? AND output_index=?", change, d.TransactionHash, d.OutputIndex)
				if err != nil {
					return fmt.Errorf("backfill deposit change %s:%d: %w", d.TransactionHash, d.OutputIndex, err)
				}
			}
			if len(batch) < 100 {
				break
			}
			offset = batch[len(batch)-1].CreatedAt.UnixNano() + 1
		}
	}

	for _, query := range []string{
		"CREATE INDEX IF NOT EXISTS deposits_by_chain_state_change_created ON deposits(chain, state, is_change, created_at)",
		"CREATE INDEX IF NOT EXISTS deposits_by_chain_state_change_updated ON deposits(chain, state, is_change, updated_at)",
		"CREATE INDEX IF NOT EXISTS deposits_by_holder_chain_state_change_created ON deposits(holder, chain, state, is_change, created_at)",
		"CREATE INDEX IF NOT EXISTS deposits_by_holder_chain_state_change_updated ON deposits(holder, chain, state, is_change, updated_at)",
	} {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	if err := s.writeProperty(ctx, tx, depositChangeMigrationKey, "done"); err != nil {
		return err
	}
	return tx.Commit()
}

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
