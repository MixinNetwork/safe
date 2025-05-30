package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/shopspring/decimal"
)

type OperationParams struct {
	RequestId            string
	OperationPriceAsset  string
	OperationPriceAmount decimal.Decimal
	CreatedAt            time.Time
}

var paramsCols = []string{"request_id", "price_asset", "price_amount", "created_at"}

func (s *SQLite3Store) ReadLatestOperationParams(ctx context.Context, offset time.Time) (*OperationParams, error) {
	query := fmt.Sprintf("SELECT %s FROM operation_params WHERE created_at<=? ORDER BY created_at DESC, request_id DESC LIMIT 1", strings.Join(paramsCols, ","))
	row := s.db.QueryRowContext(ctx, query, offset)

	var p OperationParams
	var price string
	err := row.Scan(&p.RequestId, &p.OperationPriceAsset, &price, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	p.OperationPriceAmount = decimal.RequireFromString(price)
	return &p, nil
}

func (s *SQLite3Store) WriteOperationParamsFromRequest(ctx context.Context, params *OperationParams, req *Request) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT request_id FROM requests WHERE request_id=? AND state=?", params.RequestId, common.RequestStateDone)
	if err != nil || existed {
		return err
	}

	amount := params.OperationPriceAmount.String()
	vals := []any{params.RequestId, params.OperationPriceAsset, amount, params.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("operation_params", paramsCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT operation_params %v", err)
	}

	err = s.finishRequest(ctx, tx, req, nil, "")
	if err != nil {
		return err
	}
	return tx.Commit()
}
