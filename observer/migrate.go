package observer

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
)

func (node *Node) Migrate(ctx context.Context) error {
	err := node.store.Migrate(ctx)
	if err != nil {
		return err
	}

	safes, err := node.store.ListAllSafes(ctx)
	if err != nil {
		return err
	}
	for _, safe := range safes {
		safe, err := node.keeperStore.ReadSafeByAddress(ctx, safe.Address)
		if err != nil {
			return err
		}
		switch safe.State {
		case common.RequestStateDone, common.RequestStateFailed:
			err = node.store.MarkAccountDeployed(ctx, safe.Address)
			logger.Printf("store.MarkAccountDeployed(%s) => %v", safe.Address, err)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *SQLite3Store) Migrate(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	key, val := "SCHEMA:VERSION:4faf897808e00865d3772ac683f484c1eb842e80", ""
	row := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&val)
	if err == nil || err != sql.ErrNoRows {
		return err
	}

	query := "ALTER TABLE accounts ADD COLUMN deployed_at TIMESTAMP;\n"
	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, "INSERT INTO properties (key, value, created_at, updated_at) VALUES (?, ?, ?, ?)", key, query, now, now)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ListAllSafes(ctx context.Context) ([]*Account, error) {
	query := fmt.Sprintf("SELECT %s FROM accounts ORDER BY created_at ASC", strings.Join(accountCols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []*Account
	for rows.Next() {
		var a Account
		err := rows.Scan(&a.Address, &a.CreatedAt, &a.Signature, &a.ApprovedAt, &a.DeployedAt, &a.MigratedAt)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, &a)
	}
	return accounts, nil
}
