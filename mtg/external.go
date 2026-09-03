package mtg

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	LiquidityRequestStateWaiting = "waiting"
	LiquidityRequestStateDone    = "done"
)

var fundingReturnMemoPrefix = []byte("MTG-FUNDING-V1:")

// ExternalBalance is MTG's aggregate accounting view of assets controlled by
// the independently operated custodian. It deliberately does not model the
// custodian's UTXOs; input selection and compaction belong to the custodian.
type ExternalBalance struct {
	AppId           string
	AssetId         string
	Amount          decimal.Decimal
	ReservedAmount  decimal.Decimal
	UpdatedSequence uint64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (b *ExternalBalance) Available() decimal.Decimal {
	if b == nil {
		return decimal.Zero
	}
	return b.Amount.Sub(b.ReservedAmount)
}

var externalBalanceCols = []string{
	"app_id", "asset_id", "amount", "reserved_amount", "updated_sequence", "created_at", "updated_at",
}

func externalBalanceFromRow(row Row) (*ExternalBalance, error) {
	var balance ExternalBalance
	var amount, reserved string
	err := row.Scan(&balance.AppId, &balance.AssetId, &amount, &reserved, &balance.UpdatedSequence, &balance.CreatedAt, &balance.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	balance.Amount, err = decimal.NewFromString(amount)
	if err != nil {
		return nil, err
	}
	balance.ReservedAmount, err = decimal.NewFromString(reserved)
	if err != nil {
		return nil, err
	}
	if balance.Amount.Cmp(decimal.Zero) < 0 || balance.ReservedAmount.Cmp(decimal.Zero) < 0 || balance.ReservedAmount.Cmp(balance.Amount) > 0 {
		return nil, fmt.Errorf("invalid external balance %s %s: %s/%s", balance.AppId, balance.AssetId, balance.Amount, balance.ReservedAmount)
	}
	return &balance, nil
}

func (grp *Group) ReadExternalBalance(ctx context.Context, appId, assetId string) *ExternalBalance {
	balance, err := grp.store.ReadExternalBalance(ctx, appId, assetId)
	if err != nil {
		panic(err)
	}
	return balance
}

func (act *Action) readExternalBalanceAt(ctx context.Context, assetId string) *ExternalBalance {
	balance := act.group.ReadExternalBalance(ctx, act.AppId, assetId)
	if balance.UpdatedSequence > act.Sequence {
		panic(fmt.Errorf("external balance %s/%s updated at %d after action %d", act.AppId, assetId, balance.UpdatedSequence, act.Sequence))
	}
	return balance
}

// liquidityRequirement is produced while an application worker tries to build
// a transaction. Only the exact hot-wallet deficit and the internal outputs
// which must remain available for replay are retained.
type liquidityRequirement struct {
	AssetId          string
	Amount           decimal.Decimal
	InternalAmount   decimal.Decimal
	InternalInputIds []string
}

func (r *liquidityRequirement) clone() *liquidityRequirement {
	if r == nil {
		return nil
	}
	c := *r
	c.InternalInputIds = append([]string(nil), r.InternalInputIds...)
	return &c
}

func (r *liquidityRequirement) equal(other *liquidityRequirement) bool {
	if r == nil || other == nil {
		return r == nil && other == nil
	}
	if r.AssetId != other.AssetId || !r.Amount.Equal(other.Amount) || !r.InternalAmount.Equal(other.InternalAmount) || len(r.InternalInputIds) != len(other.InternalInputIds) {
		return false
	}
	for i, id := range r.InternalInputIds {
		if id != other.InternalInputIds[i] {
			return false
		}
	}
	return true
}

func (act *Action) requireLiquidity(ctx context.Context, assetId string, target, internal decimal.Decimal, inputs []*UnifiedOutput) bool {
	if act.liquidity != nil {
		panic(fmt.Errorf("multiple liquidity requirements for action %s", act.OutputId))
	}
	external := act.readExternalBalanceAt(ctx, assetId).Available()
	if internal.Add(external).Cmp(target) < 0 {
		return false
	}
	if act.protectedInputs == nil {
		act.protectedInputs = make(map[string]*UnifiedOutput)
	}
	for _, out := range inputs {
		act.protectedInputs[out.OutputId] = out
	}
	ids := make([]string, 0, len(act.protectedInputs))
	for id := range act.protectedInputs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	act.liquidity = &liquidityRequirement{
		AssetId:          assetId,
		Amount:           target.Sub(internal),
		InternalAmount:   internal,
		InternalInputIds: ids,
	}
	return true
}

type LiquidityRequest struct {
	RequestId      string
	ActionId       string
	AppId          string
	AssetId        string
	Amount         decimal.Decimal
	State          string
	Sequence       uint64
	ReturnOutputId string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

var liquidityRequestCols = []string{
	"request_id", "action_id", "app_id", "asset_id", "amount", "state", "sequence", "return_output_id", "created_at", "updated_at",
}

func (r *LiquidityRequest) values() []any {
	return []any{r.RequestId, r.ActionId, r.AppId, r.AssetId, r.Amount.String(), r.State, r.Sequence, r.ReturnOutputId, r.CreatedAt, r.UpdatedAt}
}

func liquidityRequestFromRow(row Row) (*LiquidityRequest, error) {
	var request LiquidityRequest
	var amount string
	err := row.Scan(&request.RequestId, &request.ActionId, &request.AppId, &request.AssetId, &amount, &request.State,
		&request.Sequence, &request.ReturnOutputId, &request.CreatedAt, &request.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	request.Amount, err = decimal.NewFromString(amount)
	return &request, err
}

func (act *Action) listSpendableOutputs(ctx context.Context, assetId string, consumedUntil uint64, limit int) []*UnifiedOutput {
	outputs := act.group.ListOutputsForAsset(ctx, act.AppId, assetId, consumedUntil, act.Sequence, SafeUtxoStateUnspent, limit)
	if !act.Restored() {
		return outputs
	}

	locked, err := act.group.store.ListReservedOutputsForAsset(ctx, act.AppId, assetId, act.OutputId, consumedUntil, act.Sequence, limit)
	if err != nil {
		panic(err)
	}
	if len(locked) > 0 {
		return locked
	}
	return outputs
}

type FundingRequest struct {
	TraceId          string
	ActionId         string
	AppId            string
	AssetId          string
	Amount           decimal.Decimal
	CustodianAddress string
	ReturnAddress    string
	ReturnMemo       []byte
	Sequence         uint64
}

func EncodeFundingReturnMemo(requestId string) []byte {
	uid, err := uuid.FromString(requestId)
	if err != nil || uid == uuid.Nil || uid.String() != requestId {
		panic(requestId)
	}
	memo := append([]byte(nil), fundingReturnMemoPrefix...)
	return append(memo, uid.Bytes()...)
}

func DecodeFundingReturnMemo(memo []byte) (string, bool) {
	if len(memo) != len(fundingReturnMemoPrefix)+16 || !bytes.HasPrefix(memo, fundingReturnMemoPrefix) {
		return "", false
	}
	uid, err := uuid.FromBytes(memo[len(fundingReturnMemoPrefix):])
	if err != nil || uid == uuid.Nil {
		return "", false
	}
	return uid.String(), true
}

func (grp *Group) createLiquidityRequest(ctx context.Context, act *Action, requirement *liquidityRequirement) error {
	if grp.custodianAddress == "" {
		return fmt.Errorf("custodian is not configured")
	}
	if requirement == nil || requirement.Amount.Cmp(decimal.Zero) <= 0 || requirement.AssetId == "" {
		return fmt.Errorf("invalid liquidity requirement %v", requirement)
	}
	requestId := UniqueId(act.OutputId, fmt.Sprintf("liquidity:%s:%d", requirement.AssetId, act.Sequence))
	request := &LiquidityRequest{
		RequestId: requestId,
		ActionId:  act.OutputId,
		AppId:     act.AppId,
		AssetId:   requirement.AssetId,
		Amount:    requirement.Amount,
		State:     LiquidityRequestStateWaiting,
		Sequence:  act.Sequence,
	}
	return grp.store.CreateLiquidityRequest(ctx, act, request, requirement.InternalInputIds)
}

func (grp *Group) ListFundingRequests(ctx context.Context, limit int) ([]*FundingRequest, error) {
	returnAddress, _, err := NewMixAddress(ctx, grp.GetMembers(), byte(grp.GetThreshold()))
	if err != nil {
		return nil, err
	}
	requests, err := grp.store.ListLiquidityRequests(ctx, LiquidityRequestStateWaiting, limit)
	if err != nil {
		return nil, err
	}
	result := make([]*FundingRequest, 0, len(requests))
	for _, request := range requests {
		result = append(result, &FundingRequest{
			TraceId:          request.RequestId,
			ActionId:         request.ActionId,
			AppId:            request.AppId,
			AssetId:          request.AssetId,
			Amount:           request.Amount,
			CustodianAddress: grp.custodianAddress,
			ReturnAddress:    returnAddress.String(),
			ReturnMemo:       EncodeFundingReturnMemo(request.RequestId),
			Sequence:         request.Sequence,
		})
	}
	return result, nil
}
