package mixinwallet

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/util"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/shopspring/decimal"
)

const (
	OutputStateUnspent = "unspent"
	OutputStateLocked  = "locked"
)

type Output struct {
	OutputId         string
	TransactionHash  string
	OutputIndex      int
	AssetId          string
	Amount           decimal.Decimal
	SendersThreshold int64
	Senders          []string
	State            string
	Sequence         uint64
	CreatedAt        time.Time
	UpdatedAt        time.Time
	SignedBy         sql.NullString
}

var outputCols = []string{"output_id", "transaction_hash", "output_index", "asset_id", "amount", "senders_threshold", "senders", "state", "sequence", "created_at", "updated_at", "signed_by"}

func outputFromRow(row Row) (*Output, error) {
	var output Output
	var senders string
	err := row.Scan(output.OutputId, output.TransactionHash, output.OutputIndex, output.AssetId, output.Amount, output.SendersThreshold, senders, output.State, output.Sequence, output.CreatedAt, output.UpdatedAt, output.SignedBy)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	output.Senders = util.SplitIds(senders, ",")
	return &output, err
}

func (s *SQLite3Store) WriteOutputsIfNotExists(ctx context.Context, outputs []*mixin.SafeUtxo) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	now := time.Now().UTC()
	for _, output := range outputs {
		existed, err := s.checkExistence(ctx, tx, "SELECT output_id FROM outputs where output_id=?", output.OutputID)
		if err != nil {
			return err
		}
		if existed {
			continue
		}

		vals := []any{output.OutputID, output.TransactionHash, output.OutputIndex, output.AssetID, output.Amount.String(), output.SendersThreshold, strings.Join(output.Senders, ","), OutputStateUnspent, output.Sequence, now, now, nil}
		err = s.execOne(ctx, tx, buildInsertionSQL("outputs", outputCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT outputs %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) LockUTXOs(ctx context.Context, trace, asset string, amount decimal.Decimal) ([]*Output, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf("SELECT %s FROM outputs WHERE asset_id=? AND state=? AND signed_by=?", strings.Join(outputCols, ","))
	outputs, err := s.listOutputsByQuery(ctx, tx, query, asset, OutputStateLocked, trace)
	if err != nil {
		return nil, err
	}
	if len(outputs) > 0 {
		return outputs, nil
	}

	query = fmt.Sprintf("SELECT %s FROM outputs WHERE asset_id=? AND state=? AND signed_by IS NULL", strings.Join(outputCols, ","))
	outputs, err = s.listOutputsByQuery(ctx, tx, query, asset, OutputStateUnspent)
	if err != nil {
		return nil, err
	}

	total := decimal.NewFromInt(0)
	var os []*Output
	for i, o := range outputs {
		total = total.Add(o.Amount)
		if total.Cmp(amount) < 0 {
			continue
		}
		os = outputs[:i+1]
		break
	}
	if len(os) == 0 {
		return nil, fmt.Errorf("insufficient outputs to send tx: %s %s %s", trace, amount.String(), total.String())
	}

	query = "UPDATE outputs SET state=?, signed_by=? WHERE output_id=? AND asset_id=? AND state=? AND signed_by IS NULL"
	for _, o := range os {
		o.State = OutputStateLocked
		o.SignedBy = sql.NullString{Valid: true, String: trace}
		err = s.execOne(ctx, tx, query, OutputStateLocked, trace, asset, OutputStateUnspent)
		if err != nil {
			return nil, fmt.Errorf("UPDATE outputs %v", err)
		}
	}

	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	return os, nil
}

func (s *SQLite3Store) listOutputsByQuery(ctx context.Context, tx *sql.Tx, query string, params ...any) ([]*Output, error) {
	rows, err := tx.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var os []*Output
	for rows.Next() {
		o, err := outputFromRow(rows)
		if err != nil {
			return nil, err
		}
		os = append(os, o)
	}
	return os, nil
}
