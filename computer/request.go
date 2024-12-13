package computer

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/shopspring/decimal"
)

const (
	RequestRoleUser     = 1
	RequestRoleSigner   = 2
	RequestRoleObserver = 3

	OperationTypeStartProcess = 0
	OperationTypeAddUser      = 1
	OperationTypeSystemCall   = 2

	OperationTypeKeygenInput  = 10
	OperationTypeKeygenOutput = 11
	OperationTypeSignInput    = 12
	OperationTypeSignOutput   = 13
)

func DecodeRequest(out *mtg.Action, b []byte, role uint8) (*store.Request, error) {
	h, err := crypto.HashFromString(out.TransactionHash)
	if err != nil {
		return nil, err
	}
	extra := common.DecodeHexOrPanic(out.Extra)
	r := &store.Request{
		Action:     extra[0],
		Id:         out.OutputId,
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
	if out.Amount.Cmp(decimal.NewFromInt(1)) < 0 {
		panic(out.TransactionHash)
	}
	switch out.AssetId {
	case node.conf.ObserverAssetId:
		return node.parseObserverRequest(out)
	case node.conf.AssetId:
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
	if len(m) < 12 {
		return nil, fmt.Errorf("node.parseObserverRequest(%v)", out)
	}
	b := common.AESDecrypt(node.aesKey[:], m)
	role := node.requestRole(out.AssetId)
	return DecodeRequest(out, b, role)
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
	b := common.AESDecrypt(node.aesKey[:], m)
	role := node.requestRole(out.AssetId)
	return DecodeRequest(out, b, role)
}

func (node *Node) parseUserRequest(out *mtg.Action) (*store.Request, error) {
	a, m := mtg.DecodeMixinExtraHEX(out.Extra)
	if a != node.conf.AppId {
		panic(out.Extra)
	}
	if m == nil {
		return nil, fmt.Errorf("node.parseHolderRequest(%v)", out)
	}
	role := node.requestRole(out.AssetId)
	return DecodeRequest(out, m, role)
}
