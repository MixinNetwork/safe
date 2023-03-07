package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
)

type SignatureRequest struct {
	RequestId       string
	TransactionHash string
	OutputIndex     int
	Signer          string
	Curve           byte
	Message         string
	Signature       sql.NullString
	State           int
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

var signatureCols = []string{"request_id", "transaction_hash", "output_index", "signer", "curve", "message", "signature", "state", "created_at", "updated_at"}

func (s *SQLite3Store) WriteSignatureRequestsWithRequest(ctx context.Context, requests []*SignatureRequest, transactionHash string, req *common.Request) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE transactions SET state=?, updated_at=? WHERE transaction_hash=?",
		common.RequestStatePending, req.CreatedAt, transactionHash)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	for _, r := range requests {
		vals := []any{r.RequestId, r.TransactionHash, r.OutputIndex, r.Signer, r.Curve, r.Message, r.Signature, r.State, r.CreatedAt, r.UpdatedAt}
		err = s.execOne(ctx, tx, buildInsertionSQL("signature_requests", signatureCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT signature_requests %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) FinishSignatureRequest(ctx context.Context, req *common.Request) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = s.execOne(ctx, tx, "UPDATE signature_requests SET signature=?, state=?, updated_at=? WHERE request_id=? AND state=?",
		req.Extra, common.RequestStatePending, req.CreatedAt, req.Id, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE signature_requests %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) FinishTransactionSignaturesWithRequest(ctx context.Context, transactionHash, psbt string, req *common.Request, num int64) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, "UPDATE signature_requests SET state=?, updated_at=? WHERE transaction_hash=?",
		common.RequestStateDone, req.CreatedAt, transactionHash)
	if err != nil {
		return fmt.Errorf("UPDATE signature_requests %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE transactions SET raw_transaction=?, state=?, updated_at=? WHERE transaction_hash=?",
		psbt, common.RequestStateDone, req.CreatedAt, transactionHash)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	err = s.execMultiple(ctx, tx, num, "UPDATE bitcoin_outputs SET state=?, updated_at=? WHERE spent_by=?",
		common.RequestStateDone, req.CreatedAt, transactionHash)
	if err != nil {
		return fmt.Errorf("UPDATE bitcoin_outputs %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?",
		common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadSignatureRequestByTransactionIndex(ctx context.Context, transactionHash string, index int) (*SignatureRequest, error) {
	var r SignatureRequest
	query := fmt.Sprintf("SELECT %s FROM signature_requests WHERE transaction_hash=? AND output_index=?", strings.Join(signatureCols, ","))
	row := s.db.QueryRowContext(ctx, query, transactionHash, index)
	err := row.Scan(&r.RequestId, &r.TransactionHash, &r.OutputIndex, &r.Signer, &r.Curve, &r.Message, &r.Signature, &r.State, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &r, err
}

func (s *SQLite3Store) ReadSignatureRequest(ctx context.Context, id string) (*SignatureRequest, error) {
	var r SignatureRequest
	query := fmt.Sprintf("SELECT %s FROM signature_requests WHERE request_id=?", strings.Join(signatureCols, ","))
	row := s.db.QueryRowContext(ctx, query, id)
	err := row.Scan(&r.RequestId, &r.TransactionHash, &r.OutputIndex, &r.Signer, &r.Curve, &r.Message, &r.Signature, &r.State, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &r, err
}

func (s *SQLite3Store) ListAllSignaturesForTransaction(ctx context.Context, transactionHash string, state int) (map[int]*SignatureRequest, error) {
	query := fmt.Sprintf("SELECT %s FROM signature_requests WHERE transaction_hash=? AND state=?", strings.Join(signatureCols, ","))
	rows, err := s.db.QueryContext(ctx, query, transactionHash, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rm := make(map[int]*SignatureRequest)
	for rows.Next() {
		var r SignatureRequest
		err := rows.Scan(&r.RequestId, &r.TransactionHash, &r.OutputIndex, &r.Signer, &r.Curve, &r.Message, &r.Signature, &r.State, &r.CreatedAt, &r.UpdatedAt)
		if err != nil {
			return nil, err
		}
		if state != common.RequestStateInitial && rm[r.OutputIndex] != nil {
			panic(transactionHash)
		}
		rm[r.OutputIndex] = &r
	}

	return rm, nil
}
