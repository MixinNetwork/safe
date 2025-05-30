package computer

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	RequestRoleUser     = common.RequestRoleHolder
	RequestRoleSigner   = common.RequestRoleSigner
	RequestRoleObserver = common.RequestRoleObserver

	FlagConfirmCallSuccess = 1
	FlagConfirmCallFail    = 2

	// user operation
	OperationTypeAddUser     = 1
	OperationTypeSystemCall  = 2
	OperationTypeUserDeposit = 3

	// observer operation
	OperationTypeSetOperationParams   = 10
	OperationTypeKeygenInput          = 11
	OperationTypeDeployExternalAssets = 12
	OperationTypeDeposit              = 13
	OperationTypeConfirmNonce         = 14
	OperationTypeConfirmCall          = 16
	OperationTypeSignInput            = 17

	// signer operation
	OperationTypeKeygenOutput = 20
	OperationTypeSignPrepare  = 21
	OperationTypeSignOutput   = 22
)

func decodeRequest(out *mtg.Action, extra []byte, role uint8) (*store.Request, error) {
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
	switch {
	case node.conf.AssetId == out.AssetId:
		if out.Amount.Cmp(decimal.NewFromInt(1)) < 0 {
			panic(out.TransactionHash)
		}
		return node.parseSignerResponse(out)
	case bot.XINAssetId == out.AssetId && node.verifyObserverRequest(out):
		return node.parseObserverRequest(out)
	default:
		return node.parseUserRequest(out)
	}
}

func (node *Node) signObserverExtra(extra []byte) []byte {
	key := crypto.Key(common.DecodeHexOrPanic(node.conf.MTG.App.SpendPrivateKey))
	msg := crypto.Sha256Hash(extra)
	sig := key.Sign(msg)
	return append(sig[:], extra...)
}

func (node *Node) verifyObserverRequest(out *mtg.Action) bool {
	_, extra := mtg.DecodeMixinExtraHEX(out.Extra)
	if len(extra) < 65 {
		return false
	}
	pub := crypto.Key(common.DecodeHexOrPanic(node.conf.ObserverPublicKey))
	sig := crypto.Signature(extra[:64])
	hash := crypto.Sha256Hash(extra[64:])
	return pub.Verify(hash, sig)
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
	return decodeRequest(out, m[64:], RequestRoleObserver)
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
	return decodeRequest(out, m, RequestRoleSigner)
}

func (node *Node) parseUserRequest(out *mtg.Action) (*store.Request, error) {
	a, m := mtg.DecodeMixinExtraHEX(out.Extra)
	if a != node.conf.AppId {
		panic(out.Extra)
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("node.parseUserRequest(%v)", out)
	}
	return decodeRequest(out, m, RequestRoleUser)
}

func (node *Node) buildRefundTxs(ctx context.Context, req *store.Request, am []*ReferencedTxAsset, receivers []string, threshold int) ([]*mtg.Transaction, string) {
	var txs []*mtg.Transaction
	for _, as := range am {
		assetId := uuid.Must(uuid.FromString(as.AssetId)).String()
		memo := fmt.Sprintf("refund:%s", assetId)
		trace := common.UniqueId(req.Id, memo)
		t := node.buildTransaction(ctx, req.Output, node.conf.AppId, assetId, receivers, threshold, as.Amount.String(), []byte(memo), trace)
		if t == nil {
			// TODO then all other assets ignored?
			return nil, assetId
		}
		txs = append(txs, t)
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
