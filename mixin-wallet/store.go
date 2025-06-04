package mixinwallet

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/shopspring/decimal"
)

type Outputs struct {
	OutputId         string
	TransactionHash  string
	OutputIndex      int
	AssetId          string
	Amount           decimal.Decimal
	SendersThreshold int64
	Senders          []string
	State            mixin.SafeUtxoState
	Sequence         uint64
	CreatedAt        time.Time
	UpdatedAt        time.Time
	SignedBy         sql.NullString
}

var outputCols = []string{"output_id", "transaction_hash", "output_index", "asset_id", "amount", "senders_threshold", "senders", "state", "sequence", "created_at", "updated_at", "signed_by"}

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

		vals := []any{output.OutputID, output.TransactionHash, output.OutputIndex, output.AssetID, output.Amount.String(), output.SendersThreshold, strings.Join(output.Senders, ","), output.State, output.Sequence, now, now, nil}
		err = s.execOne(ctx, tx, buildInsertionSQL("outputs", outputCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT outputs %v", err)
		}
	}

	return tx.Commit()
}
