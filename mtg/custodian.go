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
)

var custodianRequestPrefix = []byte("CUSTODIAN-REQUEST")

// CustodianTransferRequest is encoded in an Action extra by an authorized
// external requester. The custodian destination is never accepted from the
// Action; it always comes from the group's genesis configuration.
type CustodianTransferRequest struct {
	AssetId string
	Amount  decimal.Decimal
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
		// FIXME: If there are not enough outputs to fund the custodian transfer, finish the action as done.
		if len(outputs) < OutputsBatchSize {
			logger.Printf("handleCustodianTransferAction(%s) => %v %d", action.OutputId, request, len(outputs))
			err := grp.store.FinishAction(ctx, action.OutputId, ActionStateDone, nil)
			if err != nil {
				return true, fmt.Errorf("store.FinishAction(%s) => %v", action.OutputId, err)
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
