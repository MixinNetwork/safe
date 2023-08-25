package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid"
)

// FIXME remove this
func (s *SQLite3Store) FixOldOperationParams(ctx context.Context, chain byte) error {
	key := fmt.Sprintf("operation-params-%d", chain)
	value, err := s.ReadProperty(ctx, key)
	if err != nil || value == "" {
		return err
	}

	var params OperationParams
	err = json.Unmarshal([]byte(value), &params)
	if err != nil {
		return err
	}

	params.Chain = chain
	params.RequestId = mixin.UniqueConversationID(uuid.Nil.String(), key)
	params.CreatedAt = time.Now().UTC()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	amount := params.OperationPriceAmount.String()
	minimum := params.TransactionMinimum.String()
	vals := []any{params.RequestId, params.Chain, params.OperationPriceAsset, amount, minimum, params.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("operation_params", paramsCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT operation_params %v", err)
	}
	return tx.Commit()
}
