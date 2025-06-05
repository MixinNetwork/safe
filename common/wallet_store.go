package common

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/MixinNetwork/safe/util"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/shopspring/decimal"
)

const (
	OutputStateUnspent = "unspent"
	OutputStateLocked  = "locked"
	OutputsDrainKey    = "outputs-drain-key"
)

//go:embed wallet_schema.sql
var SCHEMA string

func OpenWalletSQLite3Store(path string) (*SQLite3Store, error) {
	db, err := OpenSQLite3Store(path, SCHEMA)
	if err != nil {
		return nil, err
	}
	return &SQLite3Store{
		db:    db,
		mutex: new(sync.Mutex),
	}, nil
}

type Output struct {
	OutputId         string
	TransactionHash  string
	OutputIndex      int
	AssetId          string
	KernelAssetId    string
	Amount           decimal.Decimal
	SendersThreshold int64
	Senders          []string
	State            string
	Sequence         uint64
	CreatedAt        time.Time
	UpdatedAt        time.Time
	SignedBy         sql.NullString

	Receivers          []string
	ReceiversThreshold int
}

var outputCols = []string{"output_id", "transaction_hash", "output_index", "asset_id", "kernel_asset_id", "amount", "senders_threshold", "senders", "state", "sequence", "created_at", "updated_at", "signed_by"}

func outputFromRow(row Row) (*Output, error) {
	var o Output
	var senders string
	err := row.Scan(&o.OutputId, &o.TransactionHash, &o.OutputIndex, &o.AssetId, &o.KernelAssetId, &o.Amount, &o.SendersThreshold, &senders, &o.State, &o.Sequence, &o.CreatedAt, &o.UpdatedAt, &o.SignedBy)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	o.Senders = util.SplitIds(senders, ",")
	return &o, err
}

func (s *SQLite3Store) WriteOutputsIfNotExists(ctx context.Context, outputs []*mixin.SafeUtxo) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer Rollback(tx)

	now := time.Now().UTC()
	for _, o := range outputs {
		if o.State != mixin.SafeUtxoStateUnspent {
			panic(o.OutputID)
		}
		existed, err := s.checkExistence(ctx, tx, "SELECT output_id FROM outputs WHERE output_id=?", o.OutputID)
		if err != nil {
			return err
		}
		if existed {
			continue
		}

		vals := []any{o.OutputID, o.TransactionHash.String(), o.OutputIndex, o.AssetID, o.KernelAssetID.String(), o.Amount.String(), o.SendersThreshold, strings.Join(o.Senders, ","), OutputStateUnspent, o.Sequence, now, now, nil}
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
	defer Rollback(tx)

	query := fmt.Sprintf("SELECT %s FROM outputs WHERE asset_id=? AND state=? AND signed_by=? ORDER BY sequence", strings.Join(outputCols, ","))
	outputs, err := s.listOutputsByQuery(ctx, tx, query, asset, OutputStateLocked, trace)
	if err != nil || len(outputs) > 0 {
		return outputs, err
	}

	query = fmt.Sprintf("SELECT %s FROM outputs WHERE asset_id=? AND state=? AND signed_by IS NULL ORDER BY sequence LIMIT 256", strings.Join(outputCols, ","))
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
		err = s.execOne(ctx, tx, query, o.State, o.SignedBy, o.OutputId, o.AssetId, OutputStateUnspent)
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
