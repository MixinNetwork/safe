package common

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/gofrs/uuid"
	"github.com/shopspring/decimal"
)

const (
	RequestRoleHolder   = 1
	RequestRoleSigner   = 2
	RequestRoleObserver = 3

	RequestStateInitial = 1
	RequestStatePending = 2
	RequestStateDone    = 3
	RequestStateFailed  = 4

	// Observer can terminate all signer and keeper nodes
	ActionTerminate = 100

	ActionObserverAddKey              = 101
	ActionObserverRequestSignerKeys   = 102
	ActionObserverUpdateNetworkStatus = 103
	ActionObserverHolderDeposit       = 104
	ActionObserverSetAccountPlan      = 106

	// For all Bitcoin like chains
	ActionBitcoinSafeProposeAccount     = 110
	ActionBitcoinSafeApproveAccount     = 111
	ActionBitcoinSafeProposeTransaction = 112
	ActionBitcoinSafeApproveTransaction = 113
	ActionBitcoinSafeRevokeTransaction  = 114
	ActionBitcoinSafeCloseAccount       = 115

	// For Mixin Kernel mainnet
	ActionMixinSafeProposeAccount     = 120
	ActionMixinSafeApproveAccount     = 121
	ActionMixinSafeProposeTransaction = 122
	ActionMixinSafeApproveTransaction = 123
	ActionMixinSafeRevokeTransaction  = 124

	// For all Ethereum like chains
	ActionEthereumSafeProposeAccount = 130
	ActionEthereumSafeApproveAccount = 131
)

type Request struct {
	Id         string
	MixinHash  crypto.Hash
	MixinIndex int
	AssetId    string
	Amount     decimal.Decimal
	Role       uint8
	Action     uint8
	Curve      uint8
	Holder     string
	Extra      string
	State      uint8
	CreatedAt  time.Time
}

func (req *Request) Operation() *Operation {
	extra := DecodeHexOrPanic(req.Extra)
	return &Operation{
		Id:     req.Id,
		Type:   req.Action,
		Curve:  req.Curve,
		Public: req.Holder,
		Extra:  extra,
	}
}

func DecodeRequest(out *mtg.Output, b []byte, role uint8) (*Request, error) {
	op, err := DecodeOperation(b)
	if err != nil {
		return nil, err
	}
	r := &Request{
		Action:     op.Type,
		Id:         op.Id,
		Curve:      op.Curve,
		Holder:     op.Public,
		Extra:      hex.EncodeToString(op.Extra),
		MixinHash:  out.TransactionHash,
		MixinIndex: out.OutputIndex,
		AssetId:    out.AssetID,
		Amount:     out.Amount,
		Role:       role,
		State:      RequestStateInitial,
		CreatedAt:  out.CreatedAt,
	}
	return r, r.VerifyFormat()
}

func (req *Request) ParseMixinRecipient(extra []byte) (time.Duration, []string, byte, error) {
	switch req.Action {
	case ActionBitcoinSafeProposeAccount:
	case ActionEthereumSafeProposeAccount:
	default:
		panic(req.Action)
	}

	dec := common.NewDecoder(extra)
	hours, err := dec.ReadUint16()
	if err != nil {
		return 0, nil, 0, err
	}
	timelock := time.Duration(hours) * time.Hour
	if timelock < bitcoin.TimeLockMinimum || timelock > bitcoin.TimeLockMaximum {
		return 0, nil, 0, fmt.Errorf("timelock %d hours", hours)
	}

	threshold, err := dec.ReadByte()
	if err != nil {
		return 0, nil, 0, err
	}
	total, err := dec.ReadByte()
	if err != nil {
		return 0, nil, 0, err
	}
	var receivers []string
	for i := byte(0); i < total; i++ {
		uid, err := readUUID(dec)
		if err != nil {
			return 0, nil, 0, err
		}
		receivers = append(receivers, uid)
	}
	if byte(len(receivers)) != total || total < threshold {
		return 0, nil, 0, fmt.Errorf("%d/%d", threshold, total)
	}
	return timelock, receivers, threshold, nil
}

func (r *Request) VerifyFormat() error {
	if r.CreatedAt.IsZero() {
		return fmt.Errorf("invalid request timestamp %v", r)
	}
	if r.Action == 0 || r.Role == 0 || r.State == 0 {
		return fmt.Errorf("invalid request action %v", r)
	}
	id := uuid.FromStringOrNil(r.AssetId)
	if id.IsNil() || id.String() != r.AssetId {
		return fmt.Errorf("invalid request asset %v", r)
	}
	if r.Amount.Cmp(decimal.New(1, -8)) < 0 {
		return fmt.Errorf("invalid request amount %v", r)
	}
	if !r.MixinHash.HasValue() {
		return fmt.Errorf("invalid request mixin %v", r)
	}
	switch r.Curve {
	case CurveSecp256k1ECDSABitcoin, CurveSecp256k1ECDSALitecoin:
		return bitcoin.VerifyHolderKey(r.Holder)
	default:
		return fmt.Errorf("invalid request curve %v", r)
	}
}

func StateName(state int) string {
	switch state {
	case RequestStateInitial:
		return "initial"
	case RequestStatePending:
		return "pending"
	case RequestStateDone:
		return "done"
	case RequestStateFailed:
		return "failed"
	default:
		panic(state)
	}
}
