package common

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
	sg "github.com/gagliardetto/solana-go"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	RequestRoleHolder   = 1
	RequestRoleSigner   = 2
	RequestRoleObserver = 3

	RequestFlagNone              = 0
	RequestFlagCustomObserverKey = 1

	RequestStateInitial = 1
	RequestStatePending = 2
	RequestStateDone    = 3
	RequestStateFailed  = 4

	ActionMigrateSafeToken = 99

	// Observer can terminate all signer and keeper nodes
	ActionTerminate = 100

	ActionObserverAddKey              = 101
	ActionObserverRequestSignerKeys   = 102
	ActionObserverUpdateNetworkStatus = 103
	ActionObserverHolderDeposit       = 104
	ActionObserverSetOperationParams  = 106

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
	ActionEthereumSafeProposeAccount     = 130
	ActionEthereumSafeApproveAccount     = 131
	ActionEthereumSafeProposeTransaction = 132
	ActionEthereumSafeApproveTransaction = 133
	ActionEthereumSafeRevokeTransaction  = 134
	ActionEthereumSafeCloseAccount       = 135
	ActionEthereumSafeRefundTransaction  = 136

	// for all Solana like chains
	ActionSolanaSafeProposeAccount     = 140
	ActionSolanaSafeApproveAccount     = 141
	ActionSolanaSafeProposeTransaction = 142
	ActionSolanaSafeApproveTransaction = 143
	ActionSolanaSafeRevokeTransaction  = 144
	ActionSolanaSafeCloseAccount       = 145

	FlagProposeNormalTransaction   = 0
	FlagProposeRecoveryTransaction = 1
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
	ExtraHEX   string
	State      uint8
	CreatedAt  time.Time
	Sequence   uint64

	Output *mtg.Action
}

type AccountProposal struct {
	Receivers []string
	Threshold byte
	Timelock  time.Duration
	Observer  string // preferred observer key, optional

	// NonceAccount is the account to be used as nonce for the create safe transaction, solana only
	NonceAccount sg.PublicKey

	// BlockHash is the block hash of the create safe transaction, solana only
	BlockHash sg.Hash

	// PayerAccount is the account to be used as payer for the create safe transaction, solana only
	PayerAccount sg.PublicKey
}

func (req *Request) Operation() *Operation {
	return &Operation{
		Id:     req.Id,
		Type:   req.Action,
		Curve:  req.Curve,
		Public: req.Holder,
		Extra:  req.ExtraBytes(),
	}
}

func (req *Request) ExtraBytes() []byte {
	return DecodeHexOrPanic(req.ExtraHEX)
}

func DecodeRequest(out *mtg.Action, b []byte, role uint8) (*Request, error) {
	op, err := DecodeOperation(b)
	if err != nil {
		return nil, err
	}
	h, err := crypto.HashFromString(out.TransactionHash)
	if err != nil {
		return nil, err
	}
	r := &Request{
		Action:     op.Type,
		Id:         op.Id,
		Curve:      op.Curve,
		Holder:     op.Public,
		ExtraHEX:   hex.EncodeToString(op.Extra),
		MixinHash:  h,
		MixinIndex: out.OutputIndex,
		AssetId:    out.AssetId,
		Amount:     out.Amount,
		Role:       role,
		State:      RequestStateInitial,
		CreatedAt:  out.SequencerCreatedAt,
		Sequence:   out.Sequence,

		Output: out,
	}
	return r, r.VerifyFormat()
}

func (req *Request) ParseMixinRecipient(ctx context.Context, client *mixin.Client, extra []byte) (*AccountProposal, error) {
	switch req.Action {
	case ActionBitcoinSafeProposeAccount:
	case ActionEthereumSafeProposeAccount:
	case ActionSolanaSafeProposeAccount:
	default:
		panic(req.Action)
	}

	dec := common.NewDecoder(extra)
	hours, err := dec.ReadUint16()
	if err != nil {
		return nil, err
	}
	timelock := time.Duration(hours) * time.Hour

	if req.Action == ActionSolanaSafeProposeAccount {
		if timelock != 0 {
			return nil, fmt.Errorf("solana timelock must be 0")
		}
	} else if timelock < bitcoin.TimeLockMinimum || timelock > bitcoin.TimeLockMaximum {
		return nil, fmt.Errorf("timelock %d hours", hours)
	}

	threshold, err := dec.ReadByte()
	if err != nil {
		return nil, err
	}
	total, err := dec.ReadByte()
	if err != nil {
		return nil, err
	}
	var receivers []string
	for i := byte(0); i < total; i++ {
		uid, err := readUUID(dec)
		if err != nil {
			return nil, err
		}
		receivers = append(receivers, uid)
	}
	if byte(len(receivers)) != total || total < threshold {
		return nil, fmt.Errorf("%d/%d", threshold, total)
	}
	arp := &AccountProposal{
		Timelock:  timelock,
		Receivers: receivers,
		Threshold: threshold,
	}

	offset := 2 + 1 + 1 + int(total)*16

	// read nonce account & payer account for solana
	if req.Action == ActionSolanaSafeProposeAccount {
		if err := dec.Read(arp.NonceAccount[:]); err != nil {
			return nil, err
		}

		if err := dec.Read(arp.BlockHash[:]); err != nil {
			return nil, err
		}

		if err := dec.Read(arp.PayerAccount[:]); err != nil {
			return nil, err
		}

		offset += sg.PublicKeyLength * 3
	}

	if observerBytes := extra[offset:]; len(observerBytes) > 0 {
		switch req.Action {
		case ActionBitcoinSafeProposeAccount:
			arp.Observer = hex.EncodeToString(observerBytes)
			err = bitcoin.VerifyHolderKey(arp.Observer)
		case ActionEthereumSafeProposeAccount:
			arp.Observer = hex.EncodeToString(observerBytes)
			err = ethereum.VerifyHolderKey(arp.Observer)
		case ActionSolanaSafeProposeAccount:
			if len(observerBytes) != sg.PublicKeyLength {
				return nil, fmt.Errorf("invalid observer length %d", len(observerBytes))
			}

			arp.Observer = sg.PublicKeyFromBytes(observerBytes).String()
		}
		if err != nil {
			return nil, fmt.Errorf("request observer %s %v", arp.Observer, err)
		}
	}

	us, err := ReadUsers(ctx, client, arp.Receivers)
	if err != nil {
		return nil, fmt.Errorf("store.ReadUsers(%s) => %v", strings.Join(arp.Receivers, ","), err)
	}
	if len(us) != len(arp.Receivers) {
		return nil, fmt.Errorf("invalid receivers: %s", strings.Join(arp.Receivers, ","))
	}
	for _, user := range us {
		if !user.HasSafe {
			return nil, fmt.Errorf("receiver %s of holder %s does not has safe", user.UserID, req.Holder)
		}
	}
	return arp, nil
}

func (r *Request) VerifyFormat() error {
	if r.CreatedAt.IsZero() {
		panic(r.Output.OutputId)
	}
	if r.Action == 0 || r.Role == 0 || r.State == 0 {
		return fmt.Errorf("invalid request action %v", r)
	}
	id, err := uuid.FromString(r.AssetId)
	if err != nil || id.IsNil() || id.String() != r.AssetId {
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
	case CurveSecp256k1ECDSAEthereum, CurveSecp256k1ECDSAMVM, CurveSecp256k1ECDSAPolygon:
		return ethereum.VerifyHolderKey(r.Holder)
	case CurveEdwards25519Default:
		return solana.VerifyHolderKey(r.Holder)
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
