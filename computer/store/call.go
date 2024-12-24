package store

import (
	"context"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
)

const (
	SystemCallStateInitial    = 0
	SystemCallStateWithdrawed = 1
	SystemCallStatePrepared   = 2
	SystemCallStateDone       = 3
)

type SystemCall struct {
	RequestId string
	UserId    string
	Raw       string
	State     int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

type SubCall struct {
	Message   string
	RequestId string
	UserId    string
	Raw       string
	State     int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

var systemCallCols = []string{"request_id", "user_id", "raw", "state", "created_at", "updated_at"}

var subCallCols = []string{"message", "request_id", "user_id", "raw", "state", "created_at", "updated_at"}

func (s *SQLite3Store) WriteUnfinishedSystemCallWithRequest(ctx context.Context, req *Request, call SystemCall, subCalls []SubCall, as []*DeployedAsset, txs []*mtg.Transaction, compaction string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.writeDeployedAssetsIfNorExist(ctx, tx, req, as)
	if err != nil {
		return err
	}

	vals := []any{call.RequestId, call.UserId, call.Raw, call.State, call.CreatedAt, call.UpdatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("system_calls", systemCallCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT system_calls %v", err)
	}
	for _, subCall := range subCalls {
		vals := []any{subCall.Message, subCall.RequestId, subCall.UserId, subCall.Raw, subCall.State, subCall.CreatedAt, subCall.UpdatedAt}
		err = s.execOne(ctx, tx, buildInsertionSQL("sub_calls", subCallCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT sub_calls %v", err)
		}
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?", common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}
	err = s.writeActionResult(ctx, tx, req.Output.OutputId, compaction, txs, req.Id)
	if err != nil {
		return err
	}

	return tx.Commit()
}
