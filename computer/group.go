package computer

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost"
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
	PrepareExtra         = "PREPARE"
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
		return nil, ""
	}
	err = req.VerifyFormat()
	if err != nil {
		panic(err)
	}
	err = node.store.WriteRequestIfNotExist(ctx, req)
	if err != nil {
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
	case OperationTypeInitMPCKey:
		return RequestRoleObserver
	case OperationTypeCreateNonce:
		return RequestRoleObserver
	case OperationTypeConfirmCall:
		return RequestRoleObserver
	case OperationTypeSignInput:
		return RequestRoleSigner
	case OperationTypeSignOutput:
		return RequestRoleSigner
	default:
		return 0
	}
}

func (node *Node) processRequest(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	switch req.Action {
	case OperationTypeKeygenInput, OperationTypeInitMPCKey, OperationTypeCreateNonce:
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
	case OperationTypeInitMPCKey:
		return node.processSignerKeyInitRequests(ctx, req)
	case OperationTypeCreateNonce:
		return node.processCreateOrUpdateNonceAccount(ctx, req)
	case OperationTypeConfirmCall:
		return node.processConfirmCall(ctx, req)
	case OperationTypeSignInput:
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
	if err != nil || len(fingerPath) != 12 || fingerPath[8] > 3 {
		return "", nil, nil, fmt.Errorf("node.readKeyByFingerPath(%s) invalid fingerprint", public)
	}
	fingerprint := hex.EncodeToString(fingerPath[:8])
	public, share, err := node.store.ReadKeyByFingerprint(ctx, fingerprint)
	return public, share, fingerPath[8:], err
}

func (node *Node) deriveByPath(_ context.Context, share, path []byte) ([]byte, []byte) {
	conf := frost.EmptyConfig(curve.Edwards25519{})
	err := conf.UnmarshalBinary(share)
	if err != nil {
		panic(err)
	}
	return common.MarshalPanic(conf.PublicPoint()), conf.ChainKey
}

func (node *Node) verifySessionHolder(_ context.Context, holder string) bool {
	point := curve.Edwards25519Point{}
	err := point.UnmarshalBinary(common.DecodeHexOrPanic(holder))
	return err == nil
}

func (node *Node) concatMessageAndSignature(msg, sig []byte) []byte {
	size := uint32(len(msg))
	if size > OperationExtraLimit {
		panic(size)
	}
	extra := binary.BigEndian.AppendUint32(nil, size)
	extra = append(extra, msg...)
	extra = append(extra, sig...)
	return extra
}

func (node *Node) checkSignatureAppended(extra []byte) bool {
	if len(extra) < 4 {
		return false
	}
	el := binary.BigEndian.Uint32(extra[:4])
	if el > 160 {
		return false
	}
	return len(extra) > int(el)+32
}

func (node *Node) verifySessionSignature(ctx context.Context, holder string, extra, share, path []byte) (bool, []byte) {
	if !node.checkSignatureAppended(extra) {
		return false, nil
	}
	el := binary.BigEndian.Uint32(extra[:4])
	msg := extra[4 : 4+el]
	sig := extra[4+el:]

	// FIXME verify 25519 default
	if len(msg) < 32 || len(sig) != 64 {
		return false, nil
	}
	group := curve.Edwards25519{}
	r := group.NewScalar()
	err := r.UnmarshalBinary(msg[:32])
	if err != nil {
		return false, nil
	}
	pub, _ := hex.DecodeString(holder)
	P := group.NewPoint()
	err = P.UnmarshalBinary(pub)
	if err != nil {
		return false, nil
	}
	P = r.ActOnBase().Add(P)
	var msig crypto.Signature
	copy(msig[:], sig)
	var mpub crypto.Key
	pub, _ = P.MarshalBinary()
	copy(mpub[:], pub)
	var hash crypto.Hash
	copy(hash[:], msg[32:])
	res := mpub.Verify(hash, msig)
	logger.Printf("mixin.Verify(%v, %x) => %t", hash, msig[:], res)
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
	case common.OperationTypeSignInput:
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

func (node *Node) parseSignerMessage(out *mtg.Action) (*common.Operation, error) {
	a, memo := mtg.DecodeMixinExtraHEX(out.Extra)
	if a != node.conf.AppId {
		panic(out.Extra)
	}

	req := decodeOperation(memo)
	req.Id = out.OutputId

	switch req.Type {
	case OperationTypeKeygenInput:
	case common.OperationTypeSignInput:
	default:
		return nil, fmt.Errorf("invalid action %d", req.Type)
	}
	return req, nil
}

func (node *Node) startOperation(ctx context.Context, op *common.Operation, members []party.ID) error {
	logger.Printf("node.startOperation(%v)", op)

	switch op.Type {
	case OperationTypeKeygenInput:
		return node.startKeygen(ctx, op)
	case common.OperationTypeSignInput:
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
		err = node.store.WriteProperty(ctx, "SIGNER:"+op.Id, hex.EncodeToString([]byte(op.Public)))
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
	logger.Printf("node.startSign(%v, %v)\n", op, members)
	if !slices.Contains(members, node.id) {
		logger.Printf("node.startSign(%v, %v) exit without committement\n", op, members)
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
	extra := node.concatMessageAndSignature(op.Extra, res.Signature)
	err = node.store.MarkSessionPending(ctx, op.Id, op.Public, extra)
	logger.Printf("store.MarkSessionPending(%v, startSign) => %x %v\n", op, extra, err)
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

func (node *Node) parseOperation(_ context.Context, memo string) (*common.Operation, error) {
	a, m := mtg.DecodeMixinExtraHEX(memo)
	if a != node.conf.AppId {
		panic(memo)
	}
	if m == nil {
		return nil, fmt.Errorf("mtg.DecodeMixinExtraHEX(%s)", memo)
	}
	op := decodeOperation(m)

	switch op.Type {
	case common.OperationTypeSignInput:
	case OperationTypeKeygenInput:
	default:
		return nil, fmt.Errorf("invalid action %d", op.Type)
	}
	return op, nil
}
