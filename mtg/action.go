package mtg

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/util"
	"github.com/shopspring/decimal"
)

const (
	ActionStateInitial    ActionState = 10
	ActionStateDone       ActionState = 11
	ActionStateRestorable ActionState = 12
)

type ActionState int

type Action struct {
	ActionState     ActionState
	restoreSequence uint64

	UnifiedOutput
	group           *Group
	consumed        map[string]uint64
	protectedInputs map[string]*UnifiedOutput
	liquidity       *liquidityRequirement
}

var actionCols = []string{"output_id", "transaction_hash", "action_state", "sequence", "restore_sequence"}

var actionJoinCols = []string{"actions.output_id", "actions.transaction_hash", "action_state", "actions.sequence", "restore_sequence", "request_id", "output_index", "asset_id", "kernel_asset_id", "amount", "senders_threshold", "senders", "receivers_threshold", "extra", "state", "created_at", "updated_at", "signers", "signed_by", "reserved_by", "trace_id", "app_id", "deposit_hash", "deposit_index"}

func (a *Action) values() []any {
	return []any{a.OutputId, a.TransactionHash, a.ActionState, a.Sequence, a.restoreSequence}
}

func (a *Action) Restored() bool {
	return a.restoreSequence > 0
}

func actionFromRow(row Row) (*Action, error) {
	var a Action
	err := row.Scan(&a.OutputId, &a.TransactionHash, &a.ActionState, &a.Sequence, &a.restoreSequence)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func actionJoinFromRow(row Row) (*Action, error) {
	var a Action
	var senders, signers string
	err := row.Scan(&a.OutputId, &a.TransactionHash, &a.ActionState, &a.Sequence, &a.restoreSequence, &a.TransactionRequestId, &a.OutputIndex, &a.AssetId, &a.KernelAssetId, &a.Amount, &a.SendersThreshold, &senders, &a.ReceiversThreshold, &a.Extra, &a.State, &a.SequencerCreatedAt, &a.updatedAt, &signers, &a.SignedBy, &a.ReservedBy, &a.TraceId, &a.AppId, &a.DepositHash, &a.DepositIndex)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	a.Senders = util.SplitIds(senders, ",")
	a.Signers = util.SplitIds(signers, ",")
	return &a, nil
}

func (a *Action) prepareForProcessing(g *Group) {
	if a.restoreSequence > a.Sequence {
		a.Sequence = a.restoreSequence
	}
	a.group = g
	a.consumed = make(map[string]uint64)
	a.protectedInputs = make(map[string]*UnifiedOutput)
	a.liquidity = nil
}

func (a *Action) TestAttachActionToGroup(g *Group) {
	a.prepareForProcessing(g)
}

func replayCheck(a *Action, txs1, txs2 []*Transaction, asset1, asset2 string, liquidity1, liquidity2 *liquidityRequirement) {
	if asset1 != asset2 {
		err := fmt.Errorf("action %s compaction asset %s => %s", a.OutputId, asset1, asset2)
		panic(err)
	}
	if !liquidity1.equal(liquidity2) {
		panic(fmt.Errorf("action %s liquidity requirement changed: %v => %v", a.OutputId, liquidity1, liquidity2))
	}
	b1 := SerializeTransactions(txs1)
	b2 := SerializeTransactions(txs2)
	if !bytes.Equal(b1, b2) {
		err := fmt.Errorf("action %s serialization %x => %x", a.OutputId, b1, b2)
		panic(err)
	}
}

func (grp *Group) checkCustodianTransferRequest(ctx context.Context, action *Action) (*CustodianTransferRequest, error) {
	_, memo := DecodeMixinExtraHEX(action.Extra)
	req, valid := decodeCustodianTransferMemo(memo)
	if !valid {
		return nil, nil
	}

	if grp.custodianAddress == "" || action.SendersThreshold != 1 || len(action.Senders) != 1 || !grp.custodianRequesters[action.Senders[0]] {
		return nil, nil
	}
	requestId := action.OutputId
	old, err := grp.store.ReadCustodianTransferByRequestId(ctx, requestId)
	if err != nil {
		return nil, err
	}
	if old != nil {
		return nil, nil
	}
	return req, nil
}

func (grp *Group) checkCompactionTransaction(ctx context.Context, action *Action) (*Transaction, bool) {
	ver, err := grp.ReadKernelTransactionUntilSufficient(ctx, action.TransactionHash)
	if err != nil {
		panic(err)
	}
	if ver.DepositData() != nil {
		d, err := grp.readOutputDepositUntilSufficient(ctx, action.OutputId)
		if err != nil {
			panic(err)
		}
		appId := grp.FindAppByEntry(DepositEntry{
			Destination: d.Destination,
			Tag:         d.Tag,
		}.UniqueKey())
		if appId == "" {
			appId = grp.GroupId
		}
		if appId != action.AppId {
			panic(action.OutputId)
		}
		return nil, false
	}
	appId, _ := DecodeMixinExtraHEX(action.Extra)
	if appId == "" {
		appId = grp.GroupId
	}
	if appId != action.AppId {
		panic(action.OutputId)
	}

	appId, err = grp.checkMTGTransaction(ctx, ver)
	if err != nil {
		panic(err)
	}
	if appId == "" {
		return nil, false
	}
	hash, err := crypto.HashFromString(action.TransactionHash)
	if err != nil {
		panic(err)
	}
	tx, err := grp.store.ReadTransactionByHash(ctx, hash)
	if err != nil {
		panic(err)
	}
	return tx, true
}

func (grp *Group) checkFundingReturn(ctx context.Context, action *Action) (*LiquidityRequest, error) {
	_, memo := DecodeMixinExtraHEX(action.Extra)
	requestId, isFundingReturn := DecodeFundingReturnMemo(memo)
	if !isFundingReturn {
		return nil, nil
	}

	request, err := grp.store.ReadLiquidityRequest(ctx, requestId)
	if err != nil {
		return nil, err
	}
	if request == nil || request.State != LiquidityRequestStateWaiting {
		return nil, nil
	}
	if action.AppId != request.AppId || action.AssetId != request.AssetId || action.Sequence <= request.Sequence ||
		action.SendersThreshold != int64(grp.custodianThreshold) || bot.HashMembers(grp.custodianMembers) != bot.HashMembers(action.Senders) {
		return nil, nil
	}
	ver, err := grp.ReadKernelTransactionUntilSufficient(ctx, action.TransactionHash)
	if err != nil {
		return nil, err
	}
	if ver.PayloadHash().String() != action.TransactionHash || ver.Asset != crypto.Sha256Hash([]byte(request.AssetId)) || action.Extra != fmt.Sprintf("%x", ver.Extra) || action.OutputIndex < 0 || action.OutputIndex >= len(ver.Outputs) {
		return nil, nil
	}
	if !action.Amount.Equal(request.Amount) || !decimal.RequireFromString(ver.Outputs[action.OutputIndex].Amount.String()).Equal(request.Amount) {
		return nil, nil
	}
	return request, nil
}

// actions queue is all the utxos ordered by their sequence
func (grp *Group) handleActionsQueue(ctx context.Context) error {
	as, err := grp.store.ListActions(ctx, ActionStateInitial, 16)
	logger.Verbosef("Group.ListActions() => %d %v", len(as), err)
	if err != nil {
		return fmt.Errorf("store.ListInitialActions() => %v", err)
	}
	for _, a := range as {
		a.prepareForProcessing(grp)

		request, err := grp.checkCustodianTransferRequest(ctx, a)
		if err != nil {
			return err
		}
		if request != nil {
			handled, err := grp.handleCustodianTransferAction(ctx, a, request)
			if err != nil {
				return err
			}
			if handled {
				continue
			}
		}

		tx, isMTG := grp.checkCompactionTransaction(ctx, a)
		if isMTG && tx == nil {
			return nil
		}
		if tx != nil && tx.compaction {
			return grp.store.RestoreAction(ctx, a, tx)
		}

		fundingRequest, err := grp.checkFundingReturn(ctx, a)
		if err != nil {
			return err
		}
		if fundingRequest != nil {
			// Restoring an older Action is a sequence barrier. Stop this batch
			// so it is replayed before any later Action can mutate aggregate
			// external balances.
			return grp.store.completeLiquidityRequest(ctx, a, fundingRequest)
		}

		wkr := grp.FindWorker(a.AppId)
		if wkr == nil {
			err = grp.store.FinishAction(ctx, a.OutputId, ActionStateDone, nil)
			if err != nil {
				return fmt.Errorf("store.FinishAction(%s) => %v", a.OutputId, err)
			}
			continue
		}

		txs, compactionAsset := wkr.ProcessOutput(ctx, a)
		liquidity := a.liquidity.clone()
		if grp.debug {
			a.prepareForProcessing(grp)
			txs2, compactionAsset2 := wkr.ProcessOutput(ctx, a)
			replayCheck(a, txs, txs2, compactionAsset, compactionAsset2, liquidity, a.liquidity)
			a.liquidity = liquidity
		}

		state := ActionStateDone
		if compactionAsset != "" && len(txs) == 0 {
			if a.liquidity != nil {
				if a.liquidity.AssetId != compactionAsset {
					return fmt.Errorf("invalid liquidity asset %s for compaction %s", a.liquidity.AssetId, compactionAsset)
				}
				err = grp.createLiquidityRequest(ctx, a, a.liquidity)
				if err != nil {
					return fmt.Errorf("group.createLiquidityRequest(%s %v) => %v", compactionAsset, a, err)
				}
				continue
			}
			t, err := grp.buildCompactionTransaction(ctx, compactionAsset, a)
			if err != nil {
				return fmt.Errorf("group.buildCompactionTransaction(%s %v) => %v", compactionAsset, a, err)
			}
			state = ActionStateRestorable
			txs = []*Transaction{t}
		} else if compactionAsset != "" {
			return fmt.Errorf("invalid compactionAsset: %s", compactionAsset)
		}

		err = a.attachTxsConsumed(ctx, txs)
		if err != nil {
			return fmt.Errorf("group.attachTxsConsumed(%v) => %v", a, err)
		}
		err = grp.checkTransactions(ctx, a, txs)
		if err != nil {
			return fmt.Errorf("group.checkTransactions(%v) => %v", a, err)
		}

		err = grp.store.FinishAction(ctx, a.OutputId, state, txs)
		if err != nil {
			return fmt.Errorf("store.FinishAction(%s %d) => %v", a.OutputId, state, err)
		}
	}
	return nil
}

func (grp *Group) checkTransactions(ctx context.Context, act *Action, txs []*Transaction) error {
	totalAmount := make(map[string]common.Integer)
	outputsLimit := make(map[string]int)
	for _, t := range txs {
		err := t.check(ctx, act)
		if err != nil {
			return err
		}

		amount, ok := totalAmount[t.AssetId]
		if !ok {
			amount = common.NewInteger(0)
		}
		totalAmount[t.AssetId] = amount.Add(common.NewIntegerFromString(t.Amount))
		outputsLimit[t.AssetId] += OutputsBatchSize
	}

	for asset, amount := range totalAmount {
		limit := outputsLimit[asset]
		if limit == 0 {
			panic(asset)
		}
		outputs := act.listSpendableOutputs(ctx, asset, 0, limit)
		total := common.NewInteger(0)
		for _, os := range outputs {
			total = total.Add(common.NewIntegerFromString(os.Amount.String()))
		}
		if total.Cmp(amount) < 0 {
			return fmt.Errorf("insufficient balance for asset %s: %s %s", asset, total, amount)
		}
	}
	return nil
}

func (action *Action) attachTxsConsumed(ctx context.Context, txs []*Transaction) error {
	for _, tx := range txs {
		if len(tx.consumedIds) == 0 {
			panic(fmt.Sprintf("tx %s has empty consumedIds", tx.TraceId))
		}
		if len(tx.consumed) > 0 {
			if len(tx.consumed) != len(tx.consumedIds) {
				panic(tx.TraceId)
			}
			continue
		}
		outputs, err := action.group.store.listOutputs(ctx, tx.consumedIds)
		if err != nil {
			return err
		}
		for _, o := range outputs {
			if o.State != SafeUtxoStateUnspent {
				panic(fmt.Sprintf("invalid output %s state %s for tx %s", o.OutputId, o.State, tx.TraceId))
			}
			if o.Sequence <= action.Sequence && o.Sequence >= action.consumed[tx.AssetId] {
				action.consumed[tx.AssetId] = o.Sequence
			} else {
				panic(fmt.Sprintf("invalid outputs sequence %d for action sequence %d or asset %s consumed %d", o.Sequence, action.Sequence, tx.AssetId, action.consumed[tx.AssetId]))
			}
		}
		tx.consumed = outputs
	}
	return nil
}
