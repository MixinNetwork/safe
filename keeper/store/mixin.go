package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/apps/mixin"
	"github.com/MixinNetwork/safe/common"
	"github.com/shopspring/decimal"
)

func (s *SQLite3Store) WriteMixinKernelOutputFromRequest(ctx context.Context, receiver, assetId string, utxo *mixin.Input, req *common.Request) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cols := []string{"transaction_hash", "output_index", "address", "asset_id", "amount", "mask", "chain", "state", "spent_by", "request_id", "created_at", "updated_at"}
	vals := []any{utxo.TransactionHash, utxo.Index, receiver, assetId, utxo.Amount.String(), utxo.Mask.String(), mixin.ChainMixinKernel, common.RequestStateInitial, nil, req.Id, req.CreatedAt, req.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("mixin_outputs", cols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT mixin_outputs %v", err)
	}
	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?", common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) ReadMixinKernelUTXO(ctx context.Context, transactionHash string, index int) (*mixin.Input, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()

	return s.readMixinKernelUTXO(ctx, tx, transactionHash, index)
}

func (s *SQLite3Store) ListAllMixinKernelUTXOsForHolderAndAsset(ctx context.Context, holder, assetId string) ([]*mixin.Input, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	safe, err := s.readSafe(ctx, tx, holder)
	if err != nil {
		return nil, err
	}

	mainInputs, err := s.listAllMixinKernelUTXOsForAddressAndAsset(ctx, safe.Address, assetId, common.RequestStateInitial)
	if err != nil {
		return nil, err
	}

	return mainInputs, nil
}

func (s *SQLite3Store) ListPendingMixinKernelUTXOsForHolderAndAsset(ctx context.Context, holder, assetId string) ([]*mixin.Input, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	safe, err := s.readSafe(ctx, tx, holder)
	if err != nil {
		return nil, err
	}

	mainInputs, err := s.listAllMixinKernelUTXOsForAddressAndAsset(ctx, safe.Address, assetId, common.RequestStatePending)
	if err != nil {
		return nil, err
	}

	return mainInputs, nil
}

func (s *SQLite3Store) listAllMixinKernelUTXOsForAddressAndAsset(ctx context.Context, receiver, assetId string, state int) ([]*mixin.Input, error) {
	query := "SELECT transaction_hash,output_index,amount,asset_id,mask FROM mixin_outputs WHERE address=? AND asset_id=? AND state=? LIMIT 256"
	rows, err := s.db.QueryContext(ctx, query, receiver, assetId, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var inputs []*mixin.Input
	for rows.Next() {
		var input mixin.Input
		var amount, asset, mask string
		err := rows.Scan(&input.TransactionHash, &input.Index, &amount, &asset, &mask)
		if err != nil {
			return nil, err
		}
		input.Amount = decimal.RequireFromString(amount)
		input.Asset = crypto.NewHash([]byte(asset))
		input.Mask, err = crypto.KeyFromString(mask)
		if err != nil {
			panic(err)
		}
		inputs = append(inputs, &input)
	}
	return inputs, nil
}

func (s *SQLite3Store) readMixinKernelUTXO(ctx context.Context, tx *sql.Tx, transactionHash string, index int) (*mixin.Input, string, error) {
	input := &mixin.Input{
		TransactionHash: transactionHash,
		Index:           uint32(index),
	}

	query := "SELECT amount,asset_id,mask,spent_by FROM mixin_outputs WHERE transaction_hash=? AND output_index=?"
	row := tx.QueryRowContext(ctx, query, transactionHash, index)

	var spent sql.NullString
	var amount, asset, mask string
	err := row.Scan(&amount, &asset, &mask, &spent)
	if err == sql.ErrNoRows {
		return nil, "", nil
	} else if err != nil {
		return nil, "", err
	}
	input.Amount = decimal.RequireFromString(amount)
	input.Asset = crypto.NewHash([]byte(asset))
	input.Mask, err = crypto.KeyFromString(mask)
	if err != nil {
		panic(err)
	}
	return input, spent.String, nil
}
