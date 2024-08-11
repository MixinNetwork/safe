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

type ActionResult struct {
	ActionId     string
	Compaction   string
	Transactions []*mtg.Transaction
	RequestId    string
	CreatedAt    time.Time
}

var requestTransactionsCols = []string{"output_id", "compaction", "transactions", "request_id", "created_at"}

func (s *SQLite3Store) FailAction(ctx context.Context, req *common.Request) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.writeActionResult(ctx, tx, req.Output.OutputId, "", nil, req.Id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) writeActionResult(ctx context.Context, tx *sql.Tx, outputId, compaction string, txs []*mtg.Transaction, requestId string) error {
	vals := []any{outputId, compaction, common.Base91Encode(mtg.SerializeTransactions(txs)), requestId, time.Now().UTC()}
	err := s.execOne(ctx, tx, buildInsertionSQL("action_results", requestTransactionsCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT action_results %v", err)
	}
	return nil
}

func (s *SQLite3Store) ReadActionResult(ctx context.Context, outputId, requestId string) (*ActionResult, bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, "SELECT state FROM requests where request_id=?", requestId)
	var state int
	err = row.Scan(&state)
	if err == sql.ErrNoRows {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	if state == common.RequestStateInitial {
		return nil, false, nil
	}

	cols := strings.Join(requestTransactionsCols, ",")
	row = tx.QueryRowContext(ctx, fmt.Sprintf("SELECT %s FROM action_results where output_id=?", cols), outputId)
	var ar ActionResult
	var data string
	err = row.Scan(&ar.ActionId, &ar.Compaction, &data, &ar.RequestId, &ar.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, true, nil
	}
	if err != nil {
		return nil, true, err
	}
	tb, err := common.Base91Decode(data)
	if err != nil {
		return nil, true, err
	}
	txs, err := mtg.DeserializeTransactions(tb)
	if err != nil {
		return nil, true, err
	}
	ar.Transactions = txs
	return &ar, true, nil
}
