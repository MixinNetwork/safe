package mtg

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/util"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

func (s *SQLite3Store) ListActions(ctx context.Context, state ActionState, limit int) ([]*Action, error) {
	query := fmt.Sprintf("SELECT %s FROM actions JOIN outputs ON actions.output_id=outputs.output_id WHERE action_state=? ORDER BY actions.sequence ASC", strings.Join(actionJoinCols, ","))
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.db.QueryContext(ctx, query, state)
	if err != nil {
		return nil, err
	}
	defer closeOrPanic(rows)

	var as []*Action
	for rows.Next() {
		a, err := actionJoinFromRow(rows)
		if err != nil {
			return nil, err
		}
		as = append(as, a)
	}
	return as, nil
}

func (s *SQLite3Store) readOutput(ctx context.Context, tx *sql.Tx, id string) (*UnifiedOutput, error) {
	query := fmt.Sprintf("SELECT %s FROM outputs WHERE output_id=?", strings.Join(outputCols, ","))
	row := tx.QueryRowContext(ctx, query, id)
	return outputFromRow(row)
}

func (s *SQLite3Store) ReadOutputById(ctx context.Context, id string) (*UnifiedOutput, error) {
	query := fmt.Sprintf("SELECT %s FROM outputs WHERE output_id=?", strings.Join(outputCols, ","))
	row := s.db.QueryRowContext(ctx, query, id)
	return outputFromRow(row)
}

func (s *SQLite3Store) ReadOutputByHashAndIndex(ctx context.Context, hash string, index uint) (*UnifiedOutput, error) {
	query := fmt.Sprintf("SELECT %s FROM outputs WHERE transaction_hash=? AND output_index=?", strings.Join(outputCols, ","))
	row := s.db.QueryRowContext(ctx, query, hash, index)
	return outputFromRow(row)
}

func (s *SQLite3Store) readAction(ctx context.Context, tx *sql.Tx, id string) (*Action, error) {
	query := fmt.Sprintf("SELECT %s FROM actions WHERE output_id=?", strings.Join(actionCols, ","))
	row := tx.QueryRowContext(ctx, query, id)
	return actionFromRow(row)
}

func (s *SQLite3Store) readRestorableAction(ctx context.Context, txn *sql.Tx, t *Transaction) (*Action, error) {
	if len(t.references) != 1 {
		return nil, nil
	}
	hash := t.references[0].String()
	query := fmt.Sprintf("SELECT %s FROM actions WHERE action_state=? AND transaction_hash=?", strings.Join(actionCols, ","))
	row := txn.QueryRowContext(ctx, query, ActionStateRestorable, hash)
	return actionFromRow(row)
}

func (s *SQLite3Store) readRestorableActionById(ctx context.Context, tx *sql.Tx, id string) (*Action, error) {
	query := fmt.Sprintf("SELECT %s FROM actions WHERE output_id=? AND action_state=?", strings.Join(actionCols, ","))
	row := tx.QueryRowContext(ctx, query, id, ActionStateRestorable)
	return actionFromRow(row)
}

func (s *SQLite3Store) finishAction(ctx context.Context, tx *sql.Tx, id string, state ActionState, ts []*Transaction) error {
	act, err := s.readAction(ctx, tx, id)
	if err != nil || act == nil || act.ActionState != ActionStateInitial {
		return fmt.Errorf("invalid action to finish => %v %v", act, err)
	}

	err = s.execOne(ctx, tx, "UPDATE actions SET action_state=? WHERE output_id=? AND action_state=?", state, id, ActionStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE actions %v", err)
	}

	for _, t := range ts {
		if len(t.consumed) == 0 {
			panic(t.TraceId)
		}
		if t.State != TransactionStateInitial {
			panic(t.TraceId)
		}
		if t.IsStorage() {
			if t.AssetId != StorageAssetId || t.Threshold != 64 || len(t.Receivers) != 1 {
				return fmt.Errorf("invalid storage transaction: %#v", t)
			}
		}
		sequence := max(act.Sequence, act.restoreSequence)
		if t.Sequence != sequence {
			panic(t.Sequence)
		}

		existed, err := s.checkExistence(ctx, tx, "SELECT trace_id FROM transactions WHERE trace_id=?", t.TraceId)
		if err != nil {
			return err
		}
		if existed {
			continue
		}

		err = s.execOne(ctx, tx, buildInsertionSQL("transactions", transactionCols), t.values()...)
		if err != nil {
			return fmt.Errorf("INSERT transactions %v", err)
		}

		now := time.Now().UTC()
		if t.custodianTransfer {
			out, err := s.readOutput(ctx, tx, t.ActionId)
			if err != nil || out == nil {
				return fmt.Errorf("read custodian transfer action %s: %v", t.ActionId, err)
			}
			_, memo := DecodeMixinExtraHEX(out.Extra)
			request, valid := decodeCustodianTransferMemo(memo)
			if !valid || request.AssetId != t.AssetId || !request.Amount.Equal(decimal.RequireFromString(t.Amount)) || t.custodianAddress == "" {
				return fmt.Errorf("invalid custodian transfer %s", t.TraceId)
			}
			err = s.execOne(ctx, tx, buildInsertionSQL("custodian_transfers", custodianTransferCols),
				t.TraceId, t.ActionId, t.ActionId, t.AppId, t.AssetId, t.Amount, t.custodianAddress,
				CustodianTransferStatePending, t.Sequence, now, now)
			if err != nil {
				return fmt.Errorf("INSERT custodian_transfers %v", err)
			}
			err = s.creditExternalBalance(ctx, tx, t.AppId, t.AssetId, request.Amount, t.Sequence, now)
			if err != nil {
				return fmt.Errorf("credit external balance %s: %v", t.TraceId, err)
			}
		}

		for _, o := range t.consumed {
			query := "UPDATE outputs SET state=?,trace_id=?,reserved_by='',updated_at=? WHERE output_id=? AND ((state=? AND reserved_by='') OR (state=? AND reserved_by=?))"
			err = s.execOne(ctx, tx, query, SafeUtxoStateAssigned, t.TraceId, now, o.OutputId,
				SafeUtxoStateUnspent, SafeUtxoStateLocked, id)
			if err != nil {
				return fmt.Errorf("UPDATE outputs %v", err)
			}
		}
	}
	return nil
}

func (s *SQLite3Store) readTransactionByTraceId(ctx context.Context, tx *sql.Tx, id string) (*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions WHERE trace_id=?", strings.Join(transactionCols, ","))
	return transactionFromRow(tx.QueryRowContext(ctx, query, id))
}

func (s *SQLite3Store) FinishAction(ctx context.Context, id string, state ActionState, ts []*Transaction) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(tx)

	err = s.finishAction(ctx, tx, id, state, ts)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) writeOutputAndAction(ctx context.Context, tx *sql.Tx, out *UnifiedOutput, state ActionState) error {
	if out.State != SafeUtxoStateUnspent || out.ReservedBy != "" {
		panic(out.OutputId)
	}
	aid := uuid.Must(uuid.FromString(out.AppId))
	if aid.String() != out.AppId {
		panic(out.AppId)
	}

	oldAct, err := s.readAction(ctx, tx, out.OutputId)
	if err != nil {
		return err
	}
	oldOutput, err := s.readOutput(ctx, tx, out.OutputId)
	if err != nil {
		return err
	}
	switch {
	case oldAct == nil && oldOutput == nil:
	case oldAct != nil && oldOutput != nil:
		return nil
	default:
		reason := fmt.Errorf("action or output exists: %v %v", oldAct, oldOutput)
		panic(reason)
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM outputs WHERE request_id=? AND transaction_hash=? AND output_index=? AND asset_id=? AND amount=? AND state=?",
		out.TransactionRequestId, out.TransactionHash, out.OutputIndex, out.AssetId, out.Amount.String(), SafeUtxoStateUnreceived)
	if err != nil {
		return err
	}

	out.updatedAt = time.Now().UTC()
	err = s.execOne(ctx, tx, buildInsertionSQL("outputs", outputCols), out.values()...)
	if err != nil {
		return fmt.Errorf("INSERT outputs %v", err)
	}

	a := Action{
		ActionState:     state,
		restoreSequence: 0,
	}
	a.Sequence = out.Sequence
	a.OutputId = out.OutputId
	a.TransactionHash = out.TransactionHash
	err = s.execOne(ctx, tx, buildInsertionSQL("actions", actionCols), a.values()...)
	if err != nil {
		return fmt.Errorf("INSERT actions %v", err)
	}

	return nil
}

func (s *SQLite3Store) WriteAction(ctx context.Context, out *UnifiedOutput, state ActionState) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(tx)

	err = s.writeOutputAndAction(ctx, tx, out, state)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) RestoreAction(ctx context.Context, act *Action, t *Transaction) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(tx)

	rAct, err := s.readRestorableAction(ctx, tx, t)
	if err != nil || rAct == nil {
		return fmt.Errorf("readRestorableAction(%v) => %v %v", t, rAct, err)
	}

	err = s.restoreAction(ctx, tx, rAct.OutputId, act.Sequence)
	if err != nil {
		return fmt.Errorf("UPDATE actions %v", err)
	}

	err = s.finishAction(ctx, tx, act.OutputId, ActionStateDone, nil)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) restoreAction(ctx context.Context, tx *sql.Tx, id string, sequence uint64) error {
	query := "UPDATE actions SET action_state=?,restore_sequence=? WHERE output_id=? AND action_state=?"
	return s.execOne(ctx, tx, query, ActionStateInitial, sequence, id, ActionStateRestorable)
}

func (s *SQLite3Store) listOutputs(ctx context.Context, ids []string) ([]*UnifiedOutput, error) {
	for _, id := range ids {
		uid, err := uuid.FromString(id)
		if err != nil || uid.String() != id {
			return nil, fmt.Errorf("invalid output id %s", id)
		}
	}
	cols := strings.Join(outputCols, ",")
	sets := "'" + strings.Join(ids, "','") + "'"
	query := fmt.Sprintf("SELECT %s FROM outputs WHERE output_id IN (%s) ORDER BY sequence ASC", cols, sets)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer closeOrPanic(rows)

	var os []*UnifiedOutput
	for rows.Next() {
		o, err := outputFromRow(rows)
		if err != nil {
			return nil, err
		}
		os = append(os, o)
	}
	return os, nil
}

func (s *SQLite3Store) ListOutputsForTransaction(ctx context.Context, traceId string, sequence uint64) ([]*UnifiedOutput, error) {
	query := fmt.Sprintf("SELECT %s FROM outputs WHERE trace_id=? AND sequence<=? ORDER BY trace_id, sequence ASC", strings.Join(outputCols, ","))
	rows, err := s.db.QueryContext(ctx, query, traceId, sequence)
	if err != nil {
		return nil, err
	}
	defer closeOrPanic(rows)

	var os []*UnifiedOutput
	for rows.Next() {
		o, err := outputFromRow(rows)
		if err != nil {
			return nil, err
		}
		os = append(os, o)
	}
	return os, nil
}

func (s *SQLite3Store) ListOutputsForAsset(ctx context.Context, appId, assetId string, consumedUntil, sequence uint64, state SafeUtxoState, limit int) ([]*UnifiedOutput, error) {
	query := fmt.Sprintf("SELECT %s FROM outputs WHERE app_id=? AND asset_id=? AND state=? AND sequence>? AND sequence<=? ORDER BY app_id, asset_id, state, sequence ASC", strings.Join(outputCols, ","))
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.db.QueryContext(ctx, query, appId, assetId, state, consumedUntil, sequence)
	if err != nil {
		return nil, err
	}
	defer closeOrPanic(rows)

	var os []*UnifiedOutput
	for rows.Next() {
		o, err := outputFromRow(rows)
		if err != nil {
			return nil, err
		}
		os = append(os, o)
	}
	return os, nil
}

func (s *SQLite3Store) ListReservedOutputsForAsset(ctx context.Context, appId, assetId, reservationId string, consumedUntil, sequence uint64, limit int) ([]*UnifiedOutput, error) {
	query := fmt.Sprintf("SELECT %s FROM outputs WHERE app_id=? AND asset_id=? AND state=? AND reserved_by=? AND sequence>? AND sequence<=? ORDER BY sequence ASC", strings.Join(outputCols, ","))
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.db.QueryContext(ctx, query, appId, assetId, SafeUtxoStateLocked, reservationId, consumedUntil, sequence)
	if err != nil {
		return nil, err
	}
	defer closeOrPanic(rows)

	var outputs []*UnifiedOutput
	for rows.Next() {
		out, err := outputFromRow(rows)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, out)
	}
	return outputs, rows.Err()
}

func (s *SQLite3Store) UpdateTxWithOutputs(ctx context.Context, t *Transaction, os []*UnifiedOutput, change common.Integer) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(tx)

	var refs []string
	for _, r := range t.references {
		refs = append(refs, r.String())
	}

	err = s.execOne(ctx, tx, "UPDATE transactions SET raw=?,hash=?,refs=?,state=?,request_id=?,updated_at=? WHERE trace_id=? AND state=?",
		hex.EncodeToString(t.Raw), t.Hash.String(), strings.Join(refs, ","), t.State, t.requestId, t.UpdatedAt, t.TraceId, TransactionStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	for _, o := range os {
		query := "UPDATE outputs SET state=?,signed_by=?,updated_at=? WHERE output_id=? AND state=? AND trace_id=?"
		err = s.execOne(ctx, tx, query, o.State, o.SignedBy, t.UpdatedAt, o.OutputId, SafeUtxoStateAssigned, t.TraceId)
		if err != nil {
			return fmt.Errorf("UPDATE outputs %v", err)
		}
	}

	if change.Sign() > 0 {
		out := &UnifiedOutput{
			OutputId:             UniqueId(t.TraceId, "change"),
			TransactionRequestId: t.TraceId,
			TransactionHash:      t.Hash.String(),
			OutputIndex:          1,
			AssetId:              t.AssetId,
			Amount:               decimal.RequireFromString(change.String()),
			State:                SafeUtxoStateUnreceived,
			Sequence:             uint64(time.Now().UnixMicro()),
			AppId:                t.AppId,
		}
		err = s.execOne(ctx, tx, buildInsertionSQL("outputs", outputCols), out.values()...)
		if err != nil {
			return fmt.Errorf("INSERT outputs %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) TestUpdateOutputsState(ctx context.Context, os []*UnifiedOutput, state string) error {
	if !util.CheckTestEnvironment(ctx) {
		panic(fmt.Errorf("invalid env"))
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(tx)

	for _, o := range os {
		query := "UPDATE outputs SET state=?, updated_at=? WHERE output_id=?"
		err = s.execOne(ctx, tx, query, state, time.Now(), o.OutputId)
		if err != nil {
			return fmt.Errorf("UPDATE outputs %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) FinishTransaction(ctx context.Context, traceId string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(tx)
	now := time.Now().UTC()

	t, err := s.readTransactionByTraceId(ctx, tx, traceId)
	if err != nil || t == nil || t.State != TransactionStateSigned {
		return fmt.Errorf("invalid transaction to finish %s: %v", traceId, err)
	}
	err = s.execOne(ctx, tx, "UPDATE transactions SET state=?, updated_at=? WHERE trace_id=? AND state=?",
		TransactionStateSnapshot, now, traceId, TransactionStateSigned)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	_, err = tx.ExecContext(ctx, "UPDATE outputs SET state=?,updated_at=? WHERE trace_id=? AND state=?",
		SafeUtxoStateSpent, now, traceId, SafeUtxoStateSigned)
	if err != nil {
		return fmt.Errorf("UPDATE outputs %v", err)
	}

	existed, err := s.checkExistence(ctx, tx, "SELECT trace_id FROM custodian_transfers WHERE trace_id=?", traceId)
	if err != nil {
		return err
	}
	if existed {
		err = s.execOne(ctx, tx, "UPDATE custodian_transfers SET state=?,updated_at=? WHERE trace_id=? AND state=?",
			CustodianTransferStateDone, now, traceId, CustodianTransferStatePending)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) ConfirmWithdrawalTransaction(ctx context.Context, traceId, hash string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(tx)

	err = s.execOne(ctx, tx, "UPDATE transactions SET withdrawal_hash=?, updated_at=? WHERE trace_id=? AND state=? AND destination IS NOT NULL AND withdrawal_hash IS NULL",
		hash, time.Now(), traceId, TransactionStateSnapshot)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) readIteration(ctx context.Context, txn *sql.Tx, id string) (*Iteration, error) {
	query := fmt.Sprintf("SELECT %s FROM iterations WHERE node_id=?", strings.Join(iterationCols, ","))
	row := txn.QueryRowContext(ctx, query, id)
	return iterationFromRow(row)
}

func (s *SQLite3Store) ListIterations(ctx context.Context) ([]*Iteration, error) {
	query := fmt.Sprintf("SELECT %s FROM iterations ORDER BY node_id,created_at ASC", strings.Join(iterationCols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer closeOrPanic(rows)

	var irs []*Iteration
	for rows.Next() {
		i, err := iterationFromRow(rows)
		if err != nil {
			return nil, err
		}
		irs = append(irs, i)
	}
	return irs, nil
}

func (s *SQLite3Store) WriteIteration(ctx context.Context, ir *Iteration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(tx)

	old, err := s.readIteration(ctx, tx, ir.NodeId)
	if err != nil {
		return err
	}
	if old != nil && old.Action >= ir.Action {
		return nil
	}

	if old != nil {
		err = s.execOne(ctx, tx, "UPDATE iterations SET action=?, threshold=?, created_at=? WHERE node_id=?", ir.Action, ir.Threshold, ir.CreatedAt, ir.NodeId)
		if err != nil {
			return fmt.Errorf("UPDATE iterations %v", err)
		}
	} else {
		err = s.execOne(ctx, tx, buildInsertionSQL("iterations", iterationCols), ir.values()...)
		if err != nil {
			return fmt.Errorf("INSERT iterations %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) ListPreviousInitialTransactions(ctx context.Context, asset string, sequence uint64) ([]*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions where asset_id=? AND state=? AND sequence<? ORDER BY asset_id, state, sequence ASC", strings.Join(transactionCols, ","))
	return s.transactionsFromQuery(ctx, query, asset, TransactionStateInitial, sequence)
}

func (s *SQLite3Store) ListTransactions(ctx context.Context, state, limit int) ([]*Transaction, map[string][]*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions where state=? ORDER BY state,sequence,trace_id ASC", strings.Join(transactionCols, ","))
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	txs, err := s.transactionsFromQuery(ctx, query, state)
	if err != nil {
		return nil, nil, err
	}

	assetTxMap := make(map[string][]*Transaction)
	for _, t := range txs {
		assetTxMap[t.AssetId] = append(assetTxMap[t.AssetId], t)
	}
	return txs, assetTxMap, nil
}

func (s *SQLite3Store) ListUnconfirmedWithdrawalTransactions(ctx context.Context, limit int) ([]*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions where state=? AND destination IS NOT NULL AND withdrawal_hash IS NULL ORDER BY state,sequence,trace_id ASC", strings.Join(transactionCols, ","))
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	return s.transactionsFromQuery(ctx, query, TransactionStateSnapshot)
}

func (s *SQLite3Store) ListConfirmedWithdrawalTransactionsAfter(ctx context.Context, offset time.Time, limit int) ([]*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions where state=? AND withdrawal_hash IS NOT NULL AND updated_at>? ORDER BY updated_at ASC", strings.Join(transactionCols, ","))
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	return s.transactionsFromQuery(ctx, query, TransactionStateSnapshot, offset)
}

func (s *SQLite3Store) transactionsFromQuery(ctx context.Context, query string, params ...any) ([]*Transaction, error) {
	rows, err := s.db.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, err
	}
	defer closeOrPanic(rows)

	var ts []*Transaction
	for rows.Next() {
		t, err := transactionFromRow(rows)
		if err != nil {
			return nil, err
		}
		ts = append(ts, t)
	}
	return ts, nil
}

func (s *SQLite3Store) ReadTransactionByHash(ctx context.Context, hash crypto.Hash) (*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions WHERE hash=?", strings.Join(transactionCols, ","))
	row := s.db.QueryRowContext(ctx, query, hash.String())
	return transactionFromRow(row)
}

func (s *SQLite3Store) ReadTransactionByTraceId(ctx context.Context, id string) (*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions WHERE trace_id=?", strings.Join(transactionCols, ","))
	row := s.db.QueryRowContext(ctx, query, id)
	return transactionFromRow(row)
}

func (s *SQLite3Store) readExternalBalance(ctx context.Context, tx *sql.Tx, appId, assetId string) (*ExternalBalance, error) {
	query := fmt.Sprintf("SELECT %s FROM external_balances WHERE app_id=? AND asset_id=?", strings.Join(externalBalanceCols, ","))
	row := tx.QueryRowContext(ctx, query, appId, assetId)
	return externalBalanceFromRow(row)
}

func (s *SQLite3Store) ReadExternalBalance(ctx context.Context, appId, assetId string) (*ExternalBalance, error) {
	query := fmt.Sprintf("SELECT %s FROM external_balances WHERE app_id=? AND asset_id=?", strings.Join(externalBalanceCols, ","))
	row := s.db.QueryRowContext(ctx, query, appId, assetId)
	balance, err := externalBalanceFromRow(row)
	if err != nil || balance != nil {
		return balance, err
	}
	return &ExternalBalance{AppId: appId, AssetId: assetId}, nil
}

func (s *SQLite3Store) updateExternalBalance(ctx context.Context, tx *sql.Tx, balance *ExternalBalance, amount, reserved decimal.Decimal, sequence uint64, now time.Time) error {
	if balance == nil || amount.Cmp(decimal.Zero) < 0 || reserved.Cmp(decimal.Zero) < 0 || reserved.Cmp(amount) > 0 {
		return fmt.Errorf("invalid external balance update %v %s/%s", balance, amount, reserved)
	}
	query := `UPDATE external_balances SET amount=?,reserved_amount=?,updated_sequence=?,updated_at=?
		WHERE app_id=? AND asset_id=? AND amount=? AND reserved_amount=?`
	return s.execOne(ctx, tx, query, amount.String(), reserved.String(), sequence, now,
		balance.AppId, balance.AssetId, balance.Amount.String(), balance.ReservedAmount.String())
}

func (s *SQLite3Store) creditExternalBalance(ctx context.Context, tx *sql.Tx, appId, assetId string, amount decimal.Decimal, sequence uint64, now time.Time) error {
	if amount.Cmp(decimal.Zero) <= 0 || !amount.Shift(8).IsInteger() {
		return fmt.Errorf("invalid external balance credit %s", amount)
	}
	balance, err := s.readExternalBalance(ctx, tx, appId, assetId)
	if err != nil {
		return err
	}
	if balance == nil {
		return s.execOne(ctx, tx, buildInsertionSQL("external_balances", externalBalanceCols),
			appId, assetId, amount.String(), decimal.Zero.String(), sequence, now, now)
	}
	return s.updateExternalBalance(ctx, tx, balance, balance.Amount.Add(amount), balance.ReservedAmount, sequence, now)
}

func (s *SQLite3Store) reserveExternalBalance(ctx context.Context, tx *sql.Tx, appId, assetId string, amount decimal.Decimal, sequence uint64, now time.Time) error {
	if amount.Cmp(decimal.Zero) <= 0 {
		return fmt.Errorf("invalid external balance reservation %s", amount)
	}
	balance, err := s.readExternalBalance(ctx, tx, appId, assetId)
	if err != nil {
		return err
	}
	if balance == nil || balance.Available().Cmp(amount) < 0 {
		available := decimal.Zero
		if balance != nil {
			available = balance.Available()
		}
		return fmt.Errorf("insufficient external balance for %s/%s: %s < %s", appId, assetId, available, amount)
	}
	return s.updateExternalBalance(ctx, tx, balance, balance.Amount, balance.ReservedAmount.Add(amount), sequence, now)
}

func (s *SQLite3Store) consumeExternalBalance(ctx context.Context, tx *sql.Tx, appId, assetId string, amount decimal.Decimal, sequence uint64, now time.Time) error {
	if amount.Cmp(decimal.Zero) <= 0 {
		return fmt.Errorf("invalid external balance consumption %s", amount)
	}
	balance, err := s.readExternalBalance(ctx, tx, appId, assetId)
	if err != nil {
		return err
	}
	if balance == nil || balance.Amount.Cmp(amount) < 0 || balance.ReservedAmount.Cmp(amount) < 0 {
		return fmt.Errorf("invalid external balance consumption %s/%s %s", appId, assetId, amount)
	}
	return s.updateExternalBalance(ctx, tx, balance, balance.Amount.Sub(amount), balance.ReservedAmount.Sub(amount), sequence, now)
}

func (s *SQLite3Store) readLiquidityRequest(ctx context.Context, tx *sql.Tx, requestId string) (*LiquidityRequest, error) {
	query := fmt.Sprintf("SELECT %s FROM liquidity_requests WHERE request_id=?", strings.Join(liquidityRequestCols, ","))
	row := tx.QueryRowContext(ctx, query, requestId)
	return liquidityRequestFromRow(row)
}

func (s *SQLite3Store) ReadLiquidityRequest(ctx context.Context, requestId string) (*LiquidityRequest, error) {
	query := fmt.Sprintf("SELECT %s FROM liquidity_requests WHERE request_id=?", strings.Join(liquidityRequestCols, ","))
	row := s.db.QueryRowContext(ctx, query, requestId)
	return liquidityRequestFromRow(row)
}

func (s *SQLite3Store) ListLiquidityRequests(ctx context.Context, state string, limit int) ([]*LiquidityRequest, error) {
	query := fmt.Sprintf("SELECT %s FROM liquidity_requests WHERE state=? ORDER BY sequence,request_id", strings.Join(liquidityRequestCols, ","))
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.db.QueryContext(ctx, query, state)
	if err != nil {
		return nil, err
	}
	defer closeOrPanic(rows)

	var requests []*LiquidityRequest
	for rows.Next() {
		request, err := liquidityRequestFromRow(rows)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, rows.Err()
}

func (s *SQLite3Store) lockOutput(ctx context.Context, tx *sql.Tx, outputId, reservationId string, now time.Time) error {
	query := "UPDATE outputs SET state=?,reserved_by=?,updated_at=? WHERE output_id=? AND state=? AND reserved_by=''"
	return s.execOne(ctx, tx, query, SafeUtxoStateLocked, reservationId, now, outputId, SafeUtxoStateUnspent)
}

func (s *SQLite3Store) CreateLiquidityRequest(ctx context.Context, act *Action, request *LiquidityRequest, internalIds []string) error {
	if request == nil || request.State != LiquidityRequestStateWaiting || request.Amount.Cmp(decimal.Zero) <= 0 {
		return fmt.Errorf("invalid liquidity request %v", request)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(tx)

	storedAction, err := s.readAction(ctx, tx, act.OutputId)
	if err != nil || storedAction == nil || storedAction.ActionState != ActionStateInitial {
		return fmt.Errorf("invalid action for liquidity request %s: %v", act.OutputId, err)
	}
	if request.ActionId != act.OutputId || request.AppId != act.AppId || request.Sequence != act.Sequence {
		return fmt.Errorf("invalid liquidity request origin %s", request.RequestId)
	}

	now := time.Now().UTC()
	request.CreatedAt = now
	request.UpdatedAt = now
	err = s.execOne(ctx, tx, buildInsertionSQL("liquidity_requests", liquidityRequestCols), request.values()...)
	if err != nil {
		return fmt.Errorf("INSERT liquidity_requests %v", err)
	}

	for _, outputId := range internalIds {
		out, err := s.readOutput(ctx, tx, outputId)
		if err != nil || out == nil || out.AppId != request.AppId || out.Sequence > request.Sequence {
			return fmt.Errorf("invalid internal liquidity input %s: %v", outputId, err)
		}
		switch {
		case out.State == SafeUtxoStateUnspent && out.ReservedBy == "":
			err = s.lockOutput(ctx, tx, outputId, act.OutputId, now)
			if err != nil {
				return fmt.Errorf("lock internal output %s: %v", outputId, err)
			}
		case out.State == SafeUtxoStateLocked && out.ReservedBy == act.OutputId:
		default:
			return fmt.Errorf("invalid internal liquidity input state %s: %s/%s", outputId, out.State, out.ReservedBy)
		}
	}
	err = s.reserveExternalBalance(ctx, tx, request.AppId, request.AssetId, request.Amount, request.Sequence, now)
	if err != nil {
		return err
	}
	err = s.execOne(ctx, tx, "UPDATE actions SET action_state=? WHERE output_id=? AND action_state=?", ActionStateRestorable, act.OutputId, ActionStateInitial)
	if err != nil {
		return fmt.Errorf("reserve action for liquidity request %s: %v", request.RequestId, err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) completeLiquidityRequest(ctx context.Context, act *Action, request *LiquidityRequest) error {
	if act == nil || request == nil {
		return fmt.Errorf("invalid liquidity return %v %v", act, request)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(tx)

	rAct, err := s.readRestorableActionById(ctx, tx, request.ActionId)
	if err != nil || rAct == nil {
		return fmt.Errorf("invalid restorable action %s: %v", request.ActionId, err)
	}

	now := time.Now().UTC()
	err = s.consumeExternalBalance(ctx, tx, request.AppId, request.AssetId, request.Amount, act.Sequence, now)
	if err != nil {
		return err
	}
	err = s.lockOutput(ctx, tx, act.OutputId, request.ActionId, now)
	if err != nil {
		return fmt.Errorf("lock liquidity return output %s: %v", act.OutputId, err)
	}
	err = s.execOne(ctx, tx, "UPDATE liquidity_requests SET state=?,return_output_id=?,updated_at=? WHERE request_id=? AND state=?",
		LiquidityRequestStateDone, act.OutputId, now, request.RequestId, LiquidityRequestStateWaiting)
	if err != nil {
		return err
	}
	err = s.restoreAction(ctx, tx, rAct.OutputId, act.Sequence)
	if err != nil {
		return err
	}
	err = s.finishAction(ctx, tx, act.OutputId, ActionStateDone, nil)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite3Store) ReadCustodianTransferByRequestId(ctx context.Context, requestId string) (*CustodianTransfer, error) {
	query := fmt.Sprintf("SELECT %s FROM custodian_transfers WHERE request_id=?", strings.Join(custodianTransferCols, ","))
	row := s.db.QueryRowContext(ctx, query, requestId)
	return custodianTransferFromRow(row)
}

type Row interface {
	Scan(dest ...any) error
}

func rollBack(txn *sql.Tx) {
	err := txn.Rollback()
	const already = "transaction has already been committed or rolled back"
	if err != nil && !strings.Contains(err.Error(), already) {
		panic(err)
	}
}

func closeOrPanic(c io.Closer) {
	err := c.Close()
	if err != nil {
		panic(err)
	}
}
