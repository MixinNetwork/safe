package computer

import (
	"context"
	"encoding/binary"
	"math/big"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	KernelTimeout = 3 * time.Minute
)

func (node *Node) ProcessOutput(ctx context.Context, out *mtg.Action) ([]*mtg.Transaction, string) {
	logger.Verbosef("node.ProcessOutput(%v)", out)
	if out.SequencerCreatedAt.IsZero() {
		panic(out.OutputId)
	}
	txs1, asset1 := node.processAction(ctx, out)
	txs2, asset2 := node.processAction(ctx, out)
	mtg.ReplayCheck(out, txs1, txs2, asset1, asset2)
	return txs1, asset1
}

func (node *Node) processAction(ctx context.Context, out *mtg.Action) ([]*mtg.Transaction, string) {
	if common.CheckTestEnvironment(ctx) {
		out.TestAttachActionToGroup(node.group)
	}
	if out.Sequence < node.conf.MTG.Genesis.Epoch && !common.CheckTestEnvironment(ctx) {
		return nil, ""
	}

	isDeposit := node.verifyKernelTransaction(ctx, out)
	if isDeposit {
		return node.processDeposit(ctx, out)
	}

	req, err := node.parseRequest(out)
	logger.Printf("node.parseRequest(%v) => %v %v", out, req, err)
	if err != nil {
		return nil, ""
	}

	ar, handled, err := node.store.ReadActionResult(ctx, out.OutputId, req.Id)
	logger.Printf("store.ReadActionResult(%s %s) => %v %t %v", out.OutputId, req.Id, ar, handled, err)
	if err != nil {
		panic(err)
	}
	if ar != nil {
		return ar.Transactions, ar.Compaction
	}
	if handled {
		err = node.store.FailAction(ctx, req)
		if err != nil {
			panic(err)
		}
		return nil, ""
	}

	role := node.getActionRole(req.Action)
	if role == 0 || role != req.Role {
		logger.Printf("invalid role: %d %d", role, req.Role)
		return nil, ""
	}
	err = req.VerifyFormat()
	if err != nil {
		logger.Printf("invalid format: %v", err)
		panic(err)
	}
	err = node.store.WriteRequestIfNotExist(ctx, req)
	if err != nil {
		logger.Printf("WriteRequestIfNotExist() => %v", err)
		panic(err)
	}

	txs, asset := node.processRequest(ctx, req)
	logger.Printf("node.processRequest(%v) => %v %s", req, txs, asset)
	return txs, asset
}

func (node *Node) getActionRole(act byte) byte {
	switch act {
	case OperationTypeAddUser:
		return RequestRoleUser
	case OperationTypeSystemCall:
		return RequestRoleUser
	case OperationTypeUserDeposit:
		return RequestRoleUser
	case OperationTypeSetOperationParams:
		return RequestRoleObserver
	case OperationTypeKeygenInput:
		return RequestRoleObserver
	case OperationTypeDeployExternalAssets:
		return RequestRoleObserver
	case OperationTypeConfirmNonce:
		return RequestRoleObserver
	case OperationTypeConfirmWithdrawal:
		return RequestRoleObserver
	case OperationTypeConfirmCall:
		return RequestRoleObserver
	case OperationTypeSignInput:
		return RequestRoleObserver
	case OperationTypeDeposit:
		return RequestRoleObserver
	case OperationTypeUpdateFeeInfo:
		return RequestRoleObserver
	case OperationTypeKeygenOutput:
		return RequestRoleSigner
	case OperationTypeSignPrepare:
		return RequestRoleSigner
	case OperationTypeSignOutput:
		return RequestRoleSigner
	default:
		return 0
	}
}

func (node *Node) processRequest(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	switch req.Action {
	case OperationTypeKeygenInput, OperationTypeKeygenOutput:
	default:
		count, err := node.store.CountKeys(ctx)
		if err != nil {
			panic(err)
		}
		if count == 0 {
			logger.Printf("processRequest(%v) => store.CountKeys() => %d", req, count)
			return node.failRequest(ctx, req, "")
		}
	}

	switch req.Action {
	case OperationTypeAddUser:
		return node.processAddUser(ctx, req)
	case OperationTypeSystemCall:
		return node.processSystemCall(ctx, req)
	case OperationTypeUserDeposit:
		return node.processUserDeposit(ctx, req)
	case OperationTypeSetOperationParams:
		return node.processSetOperationParams(ctx, req)
	case OperationTypeKeygenInput:
		return node.processSignerKeygenRequests(ctx, req)
	case OperationTypeDeployExternalAssets:
		return node.processDeployExternalAssetsCall(ctx, req)
	case OperationTypeConfirmNonce:
		return node.processConfirmNonce(ctx, req)
	case OperationTypeConfirmWithdrawal:
		return node.processConfirmWithdrawal(ctx, req)
	case OperationTypeConfirmCall:
		return node.processConfirmCall(ctx, req)
	case OperationTypeSignInput:
		return node.processObserverRequestSign(ctx, req)
	case OperationTypeDeposit:
		return node.processObserverCreateDepositCall(ctx, req)
	case OperationTypeKeygenOutput:
		return node.processSignerKeygenResults(ctx, req)
	case OperationTypeSignPrepare:
		return node.processSignerPrepare(ctx, req)
	case OperationTypeSignOutput:
		return node.processSignerSignatureResponse(ctx, req)
	case OperationTypeUpdateFeeInfo:
		return node.processUpdateFeeInfo(ctx, req)
	default:
		panic(req.Action)
	}
}

func (node *Node) processSetOperationParams(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeSetOperationParams {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	if len(extra) != 24 {
		return node.failRequest(ctx, req, "")
	}

	assetId := uuid.Must(uuid.FromBytes(extra[:16]))
	abu := new(big.Int).SetUint64(binary.BigEndian.Uint64(extra[16:24]))
	amount := decimal.NewFromBigInt(abu, -8)
	params := &store.OperationParams{
		RequestId:            req.Id,
		OperationPriceAsset:  assetId.String(),
		OperationPriceAmount: amount,
		CreatedAt:            req.CreatedAt,
	}
	err := node.store.WriteOperationParamsFromRequest(ctx, params, req)
	if err != nil {
		panic(err)
	}
	return nil, ""
}

func (node *Node) processUpdateFeeInfo(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeUpdateFeeInfo {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	ratio := string(extra)

	err := node.store.WriteFeeInfoWithRequest(ctx, req, ratio)
	logger.Printf("node.WriteFeeInfoWithRequest(%s) => %v", ratio, err)
	if err != nil {
		panic(err)
	}
	return nil, ""
}

func (node *Node) timestamp(ctx context.Context) (uint64, error) {
	req, err := node.store.ReadLatestRequest(ctx)
	if err != nil || req == nil {
		return node.conf.MTG.Genesis.Epoch, err
	}
	return req.Sequence, nil
}

func (node *Node) verifyKernelTransaction(ctx context.Context, out *mtg.Action) bool {
	if common.CheckTestEnvironment(ctx) {
		return false
	}

	ver, err := common.VerifyKernelTransaction(ctx, node.group, out, KernelTimeout)
	if err != nil {
		panic(err)
	}
	return ver.DepositData() != nil
}
