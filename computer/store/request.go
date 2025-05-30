package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

type Request struct {
	Id         string
	MixinHash  crypto.Hash
	MixinIndex int
	AssetId    string
	Amount     decimal.Decimal
	Role       uint8
	Action     uint8
	ExtraHEX   string
	State      uint8
	CreatedAt  time.Time
	Sequence   uint64

	Output *mtg.Action
}

func (req *Request) ExtraBytes() []byte {
	return common.DecodeHexOrPanic(req.ExtraHEX)
}

func (r *Request) VerifyFormat() error {
	if r.CreatedAt.IsZero() {
		panic(r.Output.OutputId)
	}
	if r.Action == 0 || r.Role == 0 || r.State == 0 {
		return fmt.Errorf("invalid request action %v", r)
	}
	id, err := uuid.FromString(r.AssetId)
	if err != nil || id.IsNil() || id.String() != r.AssetId {
		return fmt.Errorf("invalid request asset %v", r)
	}
	if r.Amount.Cmp(decimal.New(1, -8)) < 0 {
		return fmt.Errorf("invalid request amount %v", r)
	}
	if !r.MixinHash.HasValue() {
		return fmt.Errorf("invalid request mixin %v", r)
	}
	return nil
}

var requestCols = []string{"request_id", "mixin_hash", "mixin_index", "asset_id", "amount", "role", "action", "extra", "state", "created_at", "updated_at", "sequence"}

func requestFromRow(row *sql.Row) (*Request, error) {
	var mh string
	var r Request
	err := row.Scan(&r.Id, &mh, &r.MixinIndex, &r.AssetId, &r.Amount, &r.Role, &r.Action, &r.ExtraHEX, &r.State, &r.CreatedAt, &time.Time{}, &r.Sequence)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	r.MixinHash, err = crypto.HashFromString(mh)
	return &r, err
}

func (s *SQLite3Store) WriteRequestIfNotExist(ctx context.Context, req *Request) error {
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

	vals := []any{req.Id, req.MixinHash.String(), req.MixinIndex, req.AssetId, req.Amount, req.Role, req.Action, req.ExtraHEX, req.State, req.CreatedAt, req.CreatedAt, req.Sequence}
	err = s.execOne(ctx, tx, buildInsertionSQL("requests", requestCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT requests %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) WriteDepositRequestIfNotExist(ctx context.Context, out *mtg.Action, state int, txs []*mtg.Transaction, compaction string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT request_id FROM requests WHERE request_id=?", out.OutputId)
	if err != nil || existed {
		return err
	}

	vals := []any{out.OutputId, out.TransactionHash, out.OutputIndex, out.AssetId, out.Amount, 0, 0, "", state, out.SequencerCreatedAt, out.SequencerCreatedAt, out.Sequence}
	err = s.execOne(ctx, tx, buildInsertionSQL("requests", requestCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT requests %v", err)
	}

	err = s.writeActionResult(ctx, tx, out.OutputId, compaction, txs, out.OutputId)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadRequest(ctx context.Context, id string) (*Request, error) {
	query := fmt.Sprintf("SELECT %s FROM requests WHERE request_id=?", strings.Join(requestCols, ","))
	row := s.db.QueryRowContext(ctx, query, id)

	return requestFromRow(row)
}

func (s *SQLite3Store) ReadRequestByHash(ctx context.Context, hash string) (*Request, error) {
	query := fmt.Sprintf("SELECT %s FROM requests WHERE mixin_hash=?", strings.Join(requestCols, ","))
	row := s.db.QueryRowContext(ctx, query, hash)

	return requestFromRow(row)
}

func (s *SQLite3Store) FailRequest(ctx context.Context, req *Request, compaction string, txs []*mtg.Transaction) error {
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

func (s *SQLite3Store) ReadLatestRequest(ctx context.Context) (*Request, error) {
	query := fmt.Sprintf("SELECT %s FROM requests ORDER BY created_at DESC, request_id DESC LIMIT 1", strings.Join(requestCols, ","))
	row := s.db.QueryRowContext(ctx, query)

	return requestFromRow(row)
}

func (s *SQLite3Store) finishRequest(ctx context.Context, tx *sql.Tx, req *Request, txs []*mtg.Transaction, compaction string) error {
	err := s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=? AND state=?",
		common.RequestStateDone, time.Now().UTC(), req.Id, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}
	return s.writeActionResult(ctx, tx, req.Output.OutputId, compaction, txs, req.Id)
}
