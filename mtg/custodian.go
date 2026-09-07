package mtg

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	CustodianTransferStatePending = "pending"
	CustodianTransferStateDone    = "done"
	CustodianTransferStateFailed  = "failed"
)

var custodianRequestPrefix = []byte("CUSTODIAN-REQUEST")
var custodianConfirmationPrefix = []byte("CUSTODIAN-CONFIRM")

// CustodianTransferRequest is encoded in an Action extra by an authorized
// external requester. The custodian destination is never accepted from the
// Action; it always comes from the group's genesis configuration.
type CustodianTransferRequest struct {
	AssetId string
	Amount  decimal.Decimal
}

// CustodianTransferConfirmation is sent by an authorized observer after the
// observer has verified the MTG transfer to the custodian on Mixin Network.
type CustodianTransferConfirmation struct {
	TraceId string
}

type CustodianTransfer struct {
	TraceId   string
	RequestId string
	ActionId  string
	AppId     string
	AssetId   string
	Amount    decimal.Decimal
	Address   string
	State     string
	Sequence  uint64
	CreatedAt time.Time
	UpdatedAt time.Time
}

var custodianTransferCols = []string{
	"trace_id", "request_id", "action_id", "app_id", "asset_id", "amount", "address", "state", "sequence", "created_at", "updated_at",
}

func (t *CustodianTransfer) values() []any {
	return []any{t.TraceId, t.RequestId, t.ActionId, t.AppId, t.AssetId, t.Amount.String(), t.Address, t.State, t.Sequence, t.CreatedAt, t.UpdatedAt}
}

func custodianTransferFromRow(row Row) (*CustodianTransfer, error) {
	var transfer CustodianTransfer
	var amount string
	err := row.Scan(&transfer.TraceId, &transfer.RequestId, &transfer.ActionId, &transfer.AppId, &transfer.AssetId, &amount,
		&transfer.Address, &transfer.State, &transfer.Sequence, &transfer.CreatedAt, &transfer.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	transfer.Amount, err = decimal.NewFromString(amount)
	return &transfer, err
}

func (s *SQLite3Store) insertCustodianTransfer(ctx context.Context, tx *sql.Tx, transfer *CustodianTransfer) error {
	if transfer == nil || transfer.TraceId == "" || transfer.RequestId == "" || transfer.ActionId == "" || transfer.AppId == "" ||
		transfer.AssetId == "" || transfer.Amount.Cmp(decimal.Zero) <= 0 || transfer.Address == "" ||
		(transfer.State != CustodianTransferStatePending && transfer.State != CustodianTransferStateFailed) {
		return fmt.Errorf("invalid custodian transfer %v", transfer)
	}
	return s.execOne(ctx, tx, buildInsertionSQL("custodian_transfers", custodianTransferCols), transfer.values()...)
}

func (s *SQLite3Store) failCustodianTransfer(ctx context.Context, transfer *CustodianTransfer) error {
	if transfer == nil || transfer.State != CustodianTransferStateFailed {
		return fmt.Errorf("invalid failed custodian transfer %v", transfer)
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(tx)

	old, err := s.readCustodianTransferByRequestId(ctx, tx, transfer.RequestId)
	if err != nil {
		return err
	}
	if old != nil {
		return nil
	}

	now := time.Now().UTC()
	transfer.CreatedAt = now
	transfer.UpdatedAt = now
	err = s.insertCustodianTransfer(ctx, tx, transfer)
	if err != nil {
		return fmt.Errorf("INSERT failed custodian transfer %v", err)
	}
	err = s.finishAction(ctx, tx, transfer.ActionId, ActionStateDone, nil)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func validateCustodianConfiguration(conf *Configuration) (string, string, []string, int, map[string]bool, error) {
	requesters := make(map[string]bool)
	if conf.Custodian.MixAddress == "" && conf.Custodian.ConversationId == "" && len(conf.Custodian.Requesters) == 0 {
		return "", "", nil, 0, requesters, nil
	}
	if conf.Custodian.MixAddress == "" {
		return "", "", nil, 0, nil, fmt.Errorf("missing custodian mix address")
	}
	if conf.Custodian.ConversationId == "" {
		return "", "", nil, 0, nil, fmt.Errorf("missing custodian conversation id")
	}
	conversationId, err := uuid.FromString(conf.Custodian.ConversationId)
	if err != nil || conversationId == uuid.Nil || conversationId.String() != conf.Custodian.ConversationId {
		return "", "", nil, 0, nil, fmt.Errorf("invalid custodian conversation id %s", conf.Custodian.ConversationId)
	}
	if len(conf.Custodian.Requesters) == 0 {
		return "", "", nil, 0, nil, fmt.Errorf("missing custodian requesters")
	}
	address, err := mixin.MixAddressFromString(conf.Custodian.MixAddress)
	if err != nil {
		return "", "", nil, 0, nil, fmt.Errorf("invalid custodian mix address: %v", err)
	}
	if len(address.Members()) == 1 || address.Threshold == 1 {
		return "", "", nil, 0, nil, fmt.Errorf("invalid custodian mix address multisigs")
	}
	for _, item := range conf.Custodian.Requesters {
		id, err := uuid.FromString(item)
		if err != nil || id.String() != item {
			return "", "", nil, 0, nil, fmt.Errorf("invalid custodian requester %s", item)
		}
		if requesters[item] {
			return "", "", nil, 0, nil, fmt.Errorf("duplicate custodian requester %s", item)
		}
		requesters[item] = true
	}
	return conversationId.String(), address.String(), address.Members(), int(address.Threshold), requesters, nil
}

func EncodeCustodianTransferMemo(assetId, amount string) []byte {
	asset, err := uuid.FromString(assetId)
	if err != nil || asset.String() != assetId {
		panic(fmt.Errorf("invalid custodian transfer request %s %s", assetId, amount))
	}
	value, err := decimal.NewFromString(amount)
	if err != nil {
		panic(fmt.Errorf("invalid custodian transfer request %s %s", assetId, amount))
	}
	value = value.Mul(decimal.New(1, 8))
	if value.Cmp(decimal.Zero) <= 0 || !value.IsInteger() || !value.BigInt().IsUint64() {
		panic(fmt.Errorf("invalid custodian transfer request %s %s", assetId, amount))
	}
	extra := append([]byte(nil), custodianRequestPrefix...)
	extra = append(extra, asset.Bytes()...)
	extra = binary.BigEndian.AppendUint64(extra, value.BigInt().Uint64())
	return extra
}

func DecodeCustodianTransferMemo(memo []byte) (*CustodianTransferRequest, bool) {
	return decodeCustodianTransferMemo(memo)
}

func decodeCustodianTransferMemo(memo []byte) (*CustodianTransferRequest, bool) {
	if len(memo) != len(custodianRequestPrefix)+16+8 || !bytes.HasPrefix(memo, custodianRequestPrefix) {
		return nil, false
	}
	offset := len(custodianRequestPrefix)
	assetId, err := uuid.FromBytes(memo[offset : offset+16])
	if err != nil || assetId == uuid.Nil {
		return nil, false
	}
	value := binary.BigEndian.Uint64(memo[offset+16:])
	amount := decimal.NewFromBigInt(new(big.Int).SetUint64(value), -8)
	if amount.Cmp(decimal.Zero) <= 0 {
		return nil, false
	}
	return &CustodianTransferRequest{AssetId: assetId.String(), Amount: amount}, true
}

func EncodeCustodianTransferConfirmationMemo(traceId string) []byte {
	id, err := uuid.FromString(traceId)
	if err != nil || id == uuid.Nil || id.String() != traceId {
		panic(fmt.Errorf("invalid custodian transfer confirmation %s", traceId))
	}
	memo := append([]byte(nil), custodianConfirmationPrefix...)
	return append(memo, id.Bytes()...)
}

func DecodeCustodianTransferConfirmationMemo(memo []byte) (*CustodianTransferConfirmation, bool) {
	if len(memo) != len(custodianConfirmationPrefix)+16 || !bytes.HasPrefix(memo, custodianConfirmationPrefix) {
		return nil, false
	}
	id, err := uuid.FromBytes(memo[len(custodianConfirmationPrefix):])
	if err != nil || id == uuid.Nil {
		return nil, false
	}
	return &CustodianTransferConfirmation{TraceId: id.String()}, true
}

// ListPendingCustodianTransfers returns transfers an observer should watch and
// confirm. TraceId is also the Mixin Safe transaction request ID.
func (grp *Group) ListPendingCustodianTransfers(ctx context.Context, limit int) ([]*CustodianTransfer, error) {
	return grp.store.ListCustodianTransfers(ctx, CustodianTransferStatePending, limit)
}

func (grp *Group) handleCustodianTransferAction(ctx context.Context, action *Action, request *CustodianTransferRequest) (bool, error) {
	traceId := UniqueId(action.OutputId, "custodian-transfer")
	state := ActionStateDone
	var txs []*Transaction
	balance := action.checkInternalAssetBalanceAt(ctx, request.AssetId)
	if balance.Cmp(request.Amount) >= 0 {
		tx := action.buildTransaction(ctx, traceId, action.AppId, request.AssetId, request.Amount.String(), "", grp.custodianMembers, grp.custodianThreshold, false)
		if tx == nil {
			panic(fmt.Errorf("failed to build funded custodian transfer %s: %s >= %s", action.OutputId, balance, request.Amount))
		}
		tx.custodianTransfer = true
		tx.custodianAddress = grp.custodianAddress
		txs = []*Transaction{tx}
	} else {
		outputs := grp.ListOutputsForAsset(ctx, action.AppId, request.AssetId, action.consumed[request.AssetId], action.Sequence, SafeUtxoStateUnspent, OutputsBatchSize)
		if len(outputs) < OutputsBatchSize {
			logger.Printf("handleCustodianTransferAction(%s) => %v %d", action.OutputId, request, len(outputs))
			transfer := &CustodianTransfer{
				TraceId:   traceId,
				RequestId: action.OutputId,
				ActionId:  action.OutputId,
				AppId:     action.AppId,
				AssetId:   request.AssetId,
				Amount:    request.Amount,
				Address:   grp.custodianAddress,
				State:     CustodianTransferStateFailed,
				Sequence:  action.Sequence,
			}
			err := grp.store.failCustodianTransfer(ctx, transfer)
			if err != nil {
				return true, fmt.Errorf("store.failCustodianTransfer(%s) => %v", action.OutputId, err)
			}
			return true, nil
		}
		compaction, err := grp.buildCompactionTransaction(ctx, request.AssetId, action)
		if err != nil {
			return true, err
		}
		state = ActionStateRestorable
		txs = []*Transaction{compaction}
	}
	err := action.attachTxsConsumed(ctx, txs)
	if err != nil {
		return true, fmt.Errorf("group.attachTxsConsumed(%v) => %v", action, err)
	}
	err = grp.checkTransactions(ctx, action, txs)
	if err != nil {
		return true, fmt.Errorf("group.checkTransactions(%v) => %v", action, err)
	}
	err = grp.store.FinishAction(ctx, action.OutputId, state, txs)
	if err != nil {
		return true, fmt.Errorf("store.FinishAction(%s %d) => %v", action.OutputId, state, err)
	}
	return true, nil
}
