package computer

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost/sign"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
)

const (
	SessionTimeout       = time.Hour
	KernelTimeout        = 3 * time.Minute
	OperationExtraLimit  = 128
	MPCFirstMessageRound = 2
)

var PrepareExtra = []byte("PREPARE")

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
	isDeposit := node.verifyKernelTransaction(ctx, out)
	if isDeposit {
		return nil, ""
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
	case OperationTypeKeygenInput:
		return RequestRoleObserver
	case OperationTypeKeygenOutput:
		return RequestRoleSigner
	case OperationTypeCreateNonce:
		return RequestRoleObserver
	case OperationTypeInitMPCKey:
		return RequestRoleObserver
	case OperationTypeCreateSubCall:
		return RequestRoleObserver
	case OperationTypeConfirmWithdrawal:
		return RequestRoleObserver
	case OperationTypeConfirmCall:
		return RequestRoleObserver
	case OperationTypeSignInput:
		return RequestRoleObserver
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
	case OperationTypeKeygenInput, OperationTypeKeygenOutput, OperationTypeInitMPCKey, OperationTypeCreateNonce:
	default:
		initialized, err := node.store.CheckMpcKeyInitialized(ctx)
		if err != nil {
			panic(err)
		}
		if !initialized {
			logger.Printf("processRequest (%v) => store.CheckMpcKeyInitialized() => %t", req, initialized)
			return node.failRequest(ctx, req, "")
		}
	}

	switch req.Action {
	case OperationTypeAddUser:
		return node.processAddUser(ctx, req)
	case OperationTypeSystemCall:
		return node.processSystemCall(ctx, req)
	case OperationTypeKeygenInput:
		return node.processSignerKeygenRequests(ctx, req)
	case OperationTypeKeygenOutput:
		return node.processSignerKeygenResults(ctx, req)
	case OperationTypeCreateNonce:
		return node.processCreateOrUpdateNonceAccount(ctx, req)
	case OperationTypeInitMPCKey:
		return node.processSignerKeyInitRequests(ctx, req)
	case OperationTypeCreateSubCall:
		return node.processCreateSubCall(ctx, req)
	case OperationTypeConfirmWithdrawal:
		return node.processConfirmWithdrawal(ctx, req)
	case OperationTypeConfirmCall:
		return node.processConfirmCall(ctx, req)
	case OperationTypeSignInput:
		return node.processObserverRequestSession(ctx, req)
	case OperationTypeSignPrepare:
		return node.processSignerPrepare(ctx, req)
	case OperationTypeSignOutput:
		return node.processSignerSignatureResponse(ctx, req)
	default:
		panic(req.Action)
	}
}

func (node *Node) timestamp(ctx context.Context) (uint64, error) {
	req, err := node.store.ReadLatestRequest(ctx)
	if err != nil || req == nil {
		return node.conf.MTG.Genesis.Epoch, err
	}
	return req.Sequence, nil
}

func (node *Node) readKeyByFingerPath(ctx context.Context, public string) (string, []byte, []byte, error) {
	fingerPath, err := hex.DecodeString(public)
	if err != nil || len(fingerPath) != 8 {
		return "", nil, nil, fmt.Errorf("node.readKeyByFingerPath(%s) invalid fingerprint", public)
	}
	fingerprint := hex.EncodeToString(fingerPath[:8])
	public, share, err := node.store.ReadKeyByFingerprint(ctx, fingerprint)
	return public, share, fingerPath[8:], err
}

func (node *Node) verifySessionHolder(_ context.Context, holder string) bool {
	point := curve.Edwards25519Point{}
	err := point.UnmarshalBinary(common.DecodeHexOrPanic(holder))
	return err == nil
}

func (node *Node) verifySessionSignature(ctx context.Context, holder string, msg, sig []byte) (bool, []byte) {
	pub := ed25519.PublicKey(common.DecodeHexOrPanic(holder))
	res := ed25519.Verify(pub, msg, sig)
	logger.Printf("ed25519.Verify(%x, %x) => %t", msg, sig[:], res)
	return res, sig
}

func (node *Node) verifySessionSignerResults(_ context.Context, session *store.Session, sessionSigners map[string]string) (bool, []byte) {
	members := node.GetMembers()
	switch session.Operation {
	case OperationTypeKeygenInput:
		var signed int
		for _, id := range members {
			public, found := sessionSigners[id]
			if found && public == session.Public && public == sessionSigners[string(node.id)] {
				signed = signed + 1
			}
		}
		exact := len(members)
		return signed >= exact, nil
	case OperationTypeSignInput:
		var signed int
		var sig []byte
		for _, id := range members {
			extra, found := sessionSigners[id]
			if sig == nil && found {
				sig = common.DecodeHexOrPanic(extra)
			}
			if found && extra != "" && hex.EncodeToString(sig) == extra {
				signed = signed + 1
			}
		}
		exact := node.threshold + 1
		return signed >= exact, sig
	default:
		panic(session.Id)
	}
}

func (node *Node) startOperation(ctx context.Context, op *common.Operation, members []party.ID) error {
	logger.Printf("node.startOperation(%v)", op)

	switch op.Type {
	case OperationTypeKeygenInput:
		return node.startKeygen(ctx, op)
	case OperationTypeSignInput:
		return node.startSign(ctx, op, members)
	default:
		panic(op.Id)
	}
}

func (node *Node) startKeygen(ctx context.Context, op *common.Operation) error {
	logger.Printf("node.startKeygen(%v)", op)
	res, err := node.frostKeygen(ctx, op.IdBytes(), curve.Edwards25519{})
	logger.Printf("node.frostKeygen(%v) => %v", op, err)
	if err != nil {
		return node.store.FailSession(ctx, op.Id)
	}
	op.Public = hex.EncodeToString(res.Public)
	saved, err := node.sendKeygenBackup(ctx, op, res.Share)
	logger.Printf("node.sendKeygenBackup(%v, %d) => %t %v", op, len(res.Share), saved, err)
	if err != nil {
		err = node.store.FailSession(ctx, op.Id)
		logger.Printf("store.FailSession(%s, startKeygen) => %v", op.Id, err)
		return err
	}
	if common.CheckTestEnvironment(ctx) {
		extra := []byte{OperationTypeKeygenOutput}
		extra = append(extra, []byte(op.Public)...)
		err = node.store.WriteProperty(ctx, "SIGNER:"+op.Id, hex.EncodeToString(extra))
		if err != nil {
			panic(err)
		}
	}
	session, err := node.store.ReadSession(ctx, op.Id)
	if err != nil {
		panic(err)
	}
	return node.store.WriteKeyIfNotExists(ctx, session, op.Public, res.Share, saved)
}

func (node *Node) startSign(ctx context.Context, op *common.Operation, members []party.ID) error {
	logger.Printf("node.startSign(%v, %v, %s)\n", op, members, string(node.id))
	if !slices.Contains(members, node.id) {
		logger.Printf("node.startSign(%v, %v, %s) exit without committement\n", op, members, string(node.id))
		return nil
	}
	public, share, _, err := node.readKeyByFingerPath(ctx, op.Public)
	logger.Printf("node.readKeyByFingerPath(%s) => %s %v", op.Public, public, err)
	if err != nil {
		return fmt.Errorf("node.readKeyByFingerPath(%s) => %v", op.Public, err)
	}
	if public == "" {
		return node.store.FailSession(ctx, op.Id)
	}
	fingerprint := op.Public[:16]
	if hex.EncodeToString(common.Fingerprint(public)) != fingerprint {
		return fmt.Errorf("node.startSign(%v) invalid sum %x %s", op, common.Fingerprint(public), fingerprint)
	}

	res, err := node.frostSign(ctx, members, public, share, op.Extra, op.IdBytes(), curve.Edwards25519{}, sign.ProtocolEd25519SHA512)
	logger.Printf("node.frostSign(%v) => %v %v", op, res, err)

	if err != nil {
		err = node.store.FailSession(ctx, op.Id)
		logger.Printf("store.FailSession(%s, startSign) => %v", op.Id, err)
		return err
	}
	if common.CheckTestEnvironment(ctx) {
		extra := []byte{OperationTypeSignOutput}
		extra = append(extra, res.Signature...)
		err = node.store.WriteProperty(ctx, "SIGNER:"+op.Id, hex.EncodeToString(extra))
		if err != nil {
			panic(err)
		}
	}
	err = node.store.MarkSessionPending(ctx, op.Id, op.Public, res.Signature)
	logger.Printf("store.MarkSessionPending(%v, startSign) => %x %v\n", op, res.Signature, err)
	return err
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
