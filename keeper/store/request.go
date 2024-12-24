package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
)

var requestCols = []string{"request_id", "mixin_hash", "mixin_index", "asset_id", "amount", "role", "action", "curve", "holder", "extra", "state", "created_at", "updated_at", "sequence"}

func requestFromRow(row *sql.Row) (*common.Request, error) {
	var mh string
	var r common.Request
	err := row.Scan(&r.Id, &mh, &r.MixinIndex, &r.AssetId, &r.Amount, &r.Role, &r.Action, &r.Curve, &r.Holder, &r.ExtraHEX, &r.State, &r.CreatedAt, &time.Time{}, &r.Sequence)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	r.MixinHash, err = crypto.HashFromString(mh)
	return &r, err
}

func (s *SQLite3Store) WriteRequestIfNotExist(ctx context.Context, req *common.Request) error {
	if req.State == 0 || req.Role == 0 {
		panic(req)
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT request_id FROM requests WHERE request_id=?", req.Id)
	if err != nil || existed {
		return err
	}

	vals := []any{req.Id, req.MixinHash.String(), req.MixinIndex, req.AssetId, req.Amount, req.Role, req.Action, req.Curve, req.Holder, req.ExtraHEX, req.State, req.CreatedAt, req.CreatedAt, req.Sequence}
	err = s.execOne(ctx, tx, buildInsertionSQL("requests", requestCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT requests %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) ReadRequest(ctx context.Context, id string) (*common.Request, error) {
	query := fmt.Sprintf("SELECT %s FROM requests WHERE request_id=?", strings.Join(requestCols, ","))
	row := s.db.QueryRowContext(ctx, query, id)

	return requestFromRow(row)
}

func (s *SQLite3Store) FailRequest(ctx context.Context, req *common.Request, compaction string, txs []*mtg.Transaction) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=? AND state=?",
		common.RequestStateFailed, time.Now().UTC(), req.Id, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	err = s.writeActionResult(ctx, tx, req.Output.OutputId, compaction, txs, req.Id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadPendingRequest(ctx context.Context) (*common.Request, error) {
	query := fmt.Sprintf("SELECT %s FROM requests WHERE state=? ORDER BY created_at ASC, request_id ASC LIMIT 1", strings.Join(requestCols, ","))
	row := s.db.QueryRowContext(ctx, query, common.RequestStateInitial)

	return requestFromRow(row)
}

func (s *SQLite3Store) ReadLatestRequest(ctx context.Context) (*common.Request, error) {
	query := fmt.Sprintf("SELECT %s FROM requests ORDER BY created_at DESC, request_id DESC LIMIT 1", strings.Join(requestCols, ","))
	row := s.db.QueryRowContext(ctx, query)

	return requestFromRow(row)
}
