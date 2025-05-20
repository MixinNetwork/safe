package signer

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid"
)

func (s *SQLite3Store) ListActionResults(ctx context.Context) (map[string][]*mtg.Transaction, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT output_id,transactions FROM action_results WHERE transactions<>'AAA'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rm := make(map[string][]*mtg.Transaction)
	for rows.Next() {
		var id, data string
		err = rows.Scan(&id, &data)
		if err != nil {
			return nil, err
		}
		tb, err := common.Base91Decode(data)
		if err != nil {
			return nil, err
		}
		txs, err := mtg.DeserializeTransactionsLegacy(tb)
		if err != nil {
			return nil, err
		}
		for _, tx := range txs {
			tx.ActionId = uuid.Nil.String()
		}
		rm[id] = txs
	}
	return rm, nil
}

func (s *SQLite3Store) Migrate(ctx context.Context, mdb *mtg.SQLite3Store) error {
	rm, err := s.ListActionResults(ctx)
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

	key, val := "SCHEMA:VERSION:COMPUTER", ""
	row := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&val)
	if err == nil || err != sql.ErrNoRows {
		return err
	}

	query := ""
	for id, txs := range rm {
		if len(txs) == 0 {
			continue
		}
		for _, tx := range txs {
			tx.ActionId = uuid.Nil.String()
			err = mdb.GetConsumedIds(ctx, tx)
			if err != nil {
				return err
			}
		}
		query += fmt.Sprintf("UPDATE action_results set transactions='%s' where output_id='%s';\n", common.Base91Encode(mtg.SerializeTransactions(txs)), id)
	}
	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, "INSERT INTO properties (key, value, created_at) VALUES (?, ?, ?)", key, query, now)
	if err != nil {
		return err
	}

	return tx.Commit()
}
