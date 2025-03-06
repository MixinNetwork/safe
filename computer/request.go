package computer

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/shopspring/decimal"
)

const (
	RequestRoleUser     = 1
	RequestRoleSigner   = 2
	RequestRoleObserver = 3

	FlagConfirmCallSuccess = 1
	FlagConfirmCallFail    = 2

	// user operation
	OperationTypeAddUser    = 1
	OperationTypeSystemCall = 2

	// observer operation
	OperationTypeSetOperationParams   = 10
	OperationTypeKeygenInput          = 11
	OperationTypeDeployExternalAssets = 12
	OperationTypeConfirmNonce         = 13
	OperationTypeConfirmWithdrawal    = 14
	OperationTypeCreateSubCall        = 15
	OperationTypeConfirmCall          = 16
	OperationTypeSignInput            = 17
	OperationTypeDeposit              = 18

	// signer operation
	OperationTypeKeygenOutput = 20
	OperationTypeSignPrepare  = 21
	OperationTypeSignOutput   = 22
)

func DecodeRequest(out *mtg.Action, extra []byte, role uint8) (*store.Request, error) {
	h, err := crypto.HashFromString(out.TransactionHash)
	if err != nil {
		return nil, err
	}
	r := &store.Request{
		Id:         out.OutputId,
		Action:     extra[0],
		ExtraHEX:   hex.EncodeToString(extra[1:]),
		MixinHash:  h,
		MixinIndex: out.OutputIndex,
		AssetId:    out.AssetId,
		Amount:     out.Amount,
		Role:       role,
		State:      common.RequestStateInitial,
		CreatedAt:  out.SequencerCreatedAt,
		Sequence:   out.Sequence,

		Output: out,
	}
	return r, r.VerifyFormat()
}

func (node *Node) parseRequest(out *mtg.Action) (*store.Request, error) {
	switch out.AssetId {
	case node.conf.ObserverAssetId:
		if out.Amount.Cmp(decimal.NewFromInt(1)) < 0 {
			panic(out.TransactionHash)
		}
		return node.parseObserverRequest(out)
	case node.conf.AssetId:
		if out.Amount.Cmp(decimal.NewFromInt(1)) < 0 {
			panic(out.TransactionHash)
		}
		return node.parseSignerResponse(out)
	default:
		return node.parseUserRequest(out)
	}
}

func (node *Node) requestRole(assetId string) uint8 {
	switch assetId {
	case node.conf.AssetId:
		return RequestRoleSigner
	case node.conf.ObserverAssetId:
		return RequestRoleObserver
	default:
		return RequestRoleUser
	}
}

func (node *Node) parseObserverRequest(out *mtg.Action) (*store.Request, error) {
	if len(out.Senders) != 1 || !node.IsMember(out.Senders[0]) {
		return nil, fmt.Errorf("parseObserverRequest(%v) %s", out, strings.Join(out.Senders, ","))
	}
	a, m := mtg.DecodeMixinExtraHEX(out.Extra)
	if a != node.conf.AppId {
		panic(out.Extra)
	}
	if len(m) < 2 {
		return nil, fmt.Errorf("node.parseObserverRequest(%v)", out)
	}
	role := node.requestRole(out.AssetId)
	return DecodeRequest(out, m, role)
}

func (node *Node) parseSignerResponse(out *mtg.Action) (*store.Request, error) {
	if len(out.Senders) != 1 || !node.IsMember(out.Senders[0]) {
		return nil, fmt.Errorf("parseSignerResponse(%v) %s", out, strings.Join(out.Senders, ","))
	}
	a, m := mtg.DecodeMixinExtraHEX(out.Extra)
	if a != node.conf.AppId {
		panic(out.Extra)
	}
	if len(m) < 12 {
		return nil, fmt.Errorf("node.parseSignerResponse(%v)", out)
	}
	role := node.requestRole(out.AssetId)
	return DecodeRequest(out, m, role)
}

func (node *Node) parseUserRequest(out *mtg.Action) (*store.Request, error) {
	a, m := mtg.DecodeMixinExtraHEX(out.Extra)
	if a != node.conf.AppId {
		panic(out.Extra)
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("node.parseUserRequest(%v)", out)
	}
	role := node.requestRole(out.AssetId)
	return DecodeRequest(out, m, role)
}

func (node *Node) buildRefundTxs(ctx context.Context, req *store.Request, am map[string]*ReferencedTxAsset, receivers []string, threshold int) ([]*mtg.Transaction, string) {
	var txs []*mtg.Transaction
	for _, as := range am {
		memo := []byte(fmt.Sprintf("refund-%s", as.Asset.AssetID))
		t := node.buildTransaction(ctx, req.Output, node.conf.AppId, req.AssetId, receivers, threshold, req.Amount.String(), memo, req.Id)
		if t == nil {
			return nil, as.Asset.AssetID
		}
		txs = append(txs, t)
	}
	return txs, ""
}

func (node *Node) refundAndFailRequest(ctx context.Context, req *store.Request, am map[string]*ReferencedTxAsset, receivers []string, threshold int) ([]*mtg.Transaction, string) {
	logger.Printf("node.refundAndFailRequest(%v) => %v %d", req, receivers, threshold)
	txs, compaction := node.buildRefundTxs(ctx, req, am, receivers, threshold)
	if compaction != "" {
		return node.failRequest(ctx, req, compaction)
	}
	err := node.store.FailRequest(ctx, req, "", txs)
	if err != nil {
		panic(err)
	}
	return txs, ""
}

func (node *Node) failRequest(ctx context.Context, req *store.Request, assetId string) ([]*mtg.Transaction, string) {
	logger.Printf("node.failRequest(%v, %s)", req, assetId)
	err := node.store.FailRequest(ctx, req, assetId, nil)
	if err != nil {
		panic(err)
	}
	return nil, assetId
}
