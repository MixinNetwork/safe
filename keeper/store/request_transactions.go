package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
)

type RequestTransactions struct {
	RequestId    string
	Compactin    string
	Transactions []*mtg.Transaction
	CreatedAt    time.Time
}

var requestTransactionsCols = []string{"request_id", "compaction", "transactions", "created_at"}

func (s *SQLite3Store) writeRequestTransactions(ctx context.Context, tx *sql.Tx, rid, compaction string, txs []*mtg.Transaction) error {
	vals := []any{rid, compaction, common.Base91Encode(mtg.SerializeTransactions(txs)), time.Now().UTC()}
	err := s.execOne(ctx, tx, buildInsertionSQL("request_transactions", requestTransactionsCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT request_transactions %v", err)
	}
	return nil
}

func (s *SQLite3Store) ReadRequestTransactions(ctx context.Context, rid string) ([]*mtg.Transaction, string, bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", false, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, "SELECT state FROM requests where request_id=?", rid)
	var state int
	err = row.Scan(&state)
	if err == sql.ErrNoRows {
		return nil, "", false, nil
	} else if err != nil {
		return nil, "", false, err
	}
	if state == common.RequestStateInitial {
		return nil, "", false, nil
	}

	cols := strings.Join(requestTransactionsCols, ",")
	row = tx.QueryRowContext(ctx, fmt.Sprintf("SELECT %s FROM request_transactions where request_id=?", cols), rid)
	var rt RequestTransactions
	var data string
	err = row.Scan(&rt.RequestId, &rt.Compactin, &data, &rt.CreatedAt)
	if err != nil {
		return nil, "", false, err
	}
	tb, err := common.Base91Decode(data)
	if err != nil {
		return nil, "", false, err
	}
	txs, err := mtg.DeserializeTransactions(tb)
	if err != nil {
		return nil, "", false, err
	}
	rt.Transactions = txs
	return rt.Transactions, rt.Compactin, true, nil
}
