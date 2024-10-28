package signer

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/protocols/cmp"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost/sign"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	SessionTimeout       = time.Hour
	KernelTimeout        = 3 * time.Minute
	OperationExtraLimit  = 128
	MPCFirstMessageRound = 2
	PrepareExtra         = "PREPARE"
)

type Session struct {
	Id         string
	MixinHash  string
	MixinIndex int
	Operation  byte
	Curve      byte
	Public     string
	Extra      string
	State      byte
	CreatedAt  time.Time
	PreparedAt sql.NullTime
}

type KeygenResult struct {
	Public []byte
	Share  []byte
	SSID   []byte
}

type SignResult struct {
	Signature []byte
	SSID      []byte
}

type Key struct {
	Public      string
	Fingerprint string
	Curve       byte
	Share       string
	SessionId   string
	CreatedAt   time.Time
	BackedUpAt  sql.NullTime
}

func (k *Key) asOperation() *common.Operation {
	return &common.Operation{
		Id:     k.SessionId,
		Type:   common.OperationTypeKeygenInput,
		Curve:  k.Curve,
		Public: k.Public,
	}
}

func (r *Session) asOperation() *common.Operation {
	return &common.Operation{
		Id:     r.Id,
		Type:   r.Operation,
		Curve:  r.Curve,
		Public: r.Public,
		Extra:  common.DecodeHexOrPanic(r.Extra),
	}
}

func (node *Node) ProcessOutput(ctx context.Context, out *mtg.Action) ([]*mtg.Transaction, string) {
	logger.Verbosef("node.ProcessOutput(%v)", out)
	if out.SequencerCreatedAt.IsZero() {
		panic(out.OutputId)
	}
	txs1, asset1 := node.processActionWithPersistence(ctx, out)
	txs2, asset2 := node.processActionWithPersistence(ctx, out)
	mtg.ReplayCheck(out, txs1, txs2, asset1, asset2)
	return txs1, asset1
}

func (node *Node) processActionWithPersistence(ctx context.Context, out *mtg.Action) ([]*mtg.Transaction, string) {
	txs, compaction, found := node.store.ReadActionResults(ctx, out.OutputId)
	if found {
		return txs, compaction
	}
	sessionId, txs, compaction := node.processAction(ctx, out)
	err := node.store.WriteActionResults(ctx, out.OutputId, txs, compaction, sessionId)
	if err != nil {
		panic(err)
	}
	return txs, compaction
}

func (node *Node) processAction(ctx context.Context, out *mtg.Action) (string, []*mtg.Transaction, string) {
	sessionId := uuid.Nil.String()
	isDeposit := node.verifyKernelTransaction(ctx, out)
	if isDeposit {
		return sessionId, nil, ""
	}
	switch out.AssetId {
	case node.conf.KeeperAssetId:
		if out.Amount.Cmp(decimal.NewFromInt(1)) < 0 {
			panic(out.TransactionHash)
		}
		op, err := node.parseOperation(ctx, out.Extra)
		logger.Printf("node.parseOperation(%v) => %v %v", out, op, err)
		if err != nil {
			return sessionId, nil, ""
		}
		sessionId = op.Id
		needsCommittment := op.Type == common.OperationTypeSignInput
		hash, err := crypto.HashFromString(out.TransactionHash)
		if err != nil {
			panic(err)
		}
		err = node.store.WriteSessionIfNotExist(ctx, op, hash, out.OutputIndex, out.SequencerCreatedAt, needsCommittment)
		if err != nil {
			panic(err)
		}
	case node.conf.AssetId:
		if len(out.Senders) != 1 || node.findMember(out.Senders[0]) < 0 {
			logger.Printf("invalid senders: %s", out.Senders)
			return sessionId, nil, ""
		}
		req, err := node.parseSignerMessage(out)
		logger.Printf("node.parseSignerMessage(%v) => %v %v", out, req, err)
		if err != nil {
			return sessionId, nil, ""
		}
		sessionId = req.Id
		if string(req.Extra) == PrepareExtra {
			err = node.processSignerPrepare(ctx, req, out)
			logger.Printf("node.processSignerPrepare(%v, %v) => %v", req, out, err)
			if err != nil {
				panic(err)
			}
		} else {
			txs, asset := node.processSignerResult(ctx, req, out)
			logger.Printf("node.processSignerResult(%v, %v) => %v %s", req, out, txs, asset)
			return sessionId, txs, asset
		}
	}
	return sessionId, nil, ""
}

func (node *Node) processSignerPrepare(ctx context.Context, op *common.Operation, out *mtg.Action) error {
	if op.Type != common.OperationTypeSignInput {
		return fmt.Errorf("node.processSignerPrepare(%v) type", op)
	}
	if string(op.Extra) != PrepareExtra {
		panic(string(op.Extra))
	}
	s, err := node.store.ReadSession(ctx, op.Id)
	if err != nil {
		return fmt.Errorf("store.ReadSession(%s) => %v", op.Id, err)
	} else if s.PreparedAt.Valid {
		return nil
	}
	err = node.store.PrepareSessionSignerIfNotExist(ctx, op.Id, out.Senders[0], out.SequencerCreatedAt)
	if err != nil {
		return fmt.Errorf("store.PrepareSessionSignerIfNotExist(%v) => %v", op, err)
	}
	signers, err := node.store.ListSessionSignerResults(ctx, op.Id)
	if err != nil {
		return fmt.Errorf("store.ListSessionSignerResults(%s) => %d %v", op.Id, len(signers), err)
	}
	if len(signers) <= node.threshold {
		return nil
	}
	err = node.store.MarkSessionPrepared(ctx, op.Id, out.SequencerCreatedAt)
	logger.Printf("node.MarkSessionPrepared(%v) => %v", op, err)
	return err
}

func (node *Node) processSignerResult(ctx context.Context, op *common.Operation, out *mtg.Action) ([]*mtg.Transaction, string) {
	session, err := node.store.ReadSession(ctx, op.Id)
	if err != nil {
		panic(fmt.Errorf("store.ReadSession(%s) => %v %v", op.Id, session, err))
	}
	if op.Curve != session.Curve || op.Type != session.Operation {
		panic(session.Id)
	}

	self := len(out.Senders) == 1 && out.Senders[0] == string(node.id)
	switch session.Operation {
	case common.OperationTypeKeygenInput:
		err = node.store.WriteSessionSignerIfNotExist(ctx, op.Id, out.Senders[0], op.Extra, out.SequencerCreatedAt, self)
		if err != nil {
			panic(fmt.Errorf("store.WriteSessionSignerIfNotExist(%v) => %v", op, err))
		}
	case common.OperationTypeSignInput:
		err = node.store.UpdateSessionSigner(ctx, op.Id, out.Senders[0], op.Extra, out.SequencerCreatedAt, self)
		if err != nil {
			panic(fmt.Errorf("store.UpdateSessionSigner(%v) => %v", op, err))
		}
	}

	signers, err := node.store.ListSessionSignerResults(ctx, op.Id)
	if err != nil {
		panic(fmt.Errorf("store.ListSessionSignerResults(%s) => %d %v", op.Id, len(signers), err))
	}
	finished, sig := node.verifySessionSignerResults(ctx, session, signers)
	logger.Printf("node.verifySessionSignerResults(%v, %d) => %t %x", session, len(signers), finished, sig)
	if !finished {
		return nil, ""
	}
	if l := len(signers); l <= node.threshold {
		panic(session.Id)
	}

	op = &common.Operation{Id: op.Id, Curve: session.Curve}
	switch session.Operation {
	case common.OperationTypeKeygenInput:
		if signers[string(node.id)] != session.Public {
			panic(session.Public)
		}
		valid := node.verifySessionHolder(ctx, session.Curve, session.Public)
		logger.Printf("node.verifySessionHolder(%v) => %t", session, valid)
		if !valid {
			return nil, ""
		}
		holder, crv, share, err := node.store.ReadKeyByFingerprint(ctx, hex.EncodeToString(common.Fingerprint(session.Public)))
		if err != nil {
			panic(err)
		}
		if holder != session.Public || crv != session.Curve {
			panic(session.Public)
		}
		public, chainCode := node.deriveByPath(ctx, crv, share, []byte{0, 0, 0, 0})
		if hex.EncodeToString(public) != session.Public {
			panic(session.Public)
		}
		op.Type = common.OperationTypeKeygenOutput
		op.Extra = append([]byte{common.RequestRoleSigner}, chainCode...)
		op.Extra = append(op.Extra, common.RequestFlagNone)
		op.Public = session.Public
	case common.OperationTypeSignInput:
		extra := common.DecodeHexOrPanic(session.Extra)
		if !node.checkSignatureAppended(extra) {
			// this could happen after resync, crash or not commited
			extra = node.concatMessageAndSignature(extra, sig)
		}
		if session.State == common.RequestStateInitial && session.PreparedAt.Valid {
			// this could happend only after crash or not commited
			err = node.store.MarkSessionPending(ctx, session.Id, session.Curve, session.Public, extra)
			logger.Printf("store.MarkSessionPending(%v, processSignerResult) => %x %v\n", session, extra, err)
			if err != nil {
				panic(err)
			}
		}

		holder, crv, share, path, err := node.readKeyByFingerPath(ctx, session.Public)
		logger.Printf("node.readKeyByFingerPath(%s) => %s %v", session.Public, holder, err)
		if err != nil {
			panic(err)
		}
		if crv != op.Curve {
			panic(session.Id)
		}
		valid, vsig := node.verifySessionSignature(ctx, op.Curve, holder, extra, share, path)
		logger.Printf("node.verifySessionSignature(%v, %s, %x, %v) => %t", session, holder, extra, path, valid)
		if !valid || !bytes.Equal(sig, vsig) {
			panic(hex.EncodeToString(vsig))
		}
		op.Type = common.OperationTypeSignOutput
		op.Public = holder
		op.Extra = vsig
	default:
		panic(session.Id)
	}

	repliedToKeeper := node.store.CheckActionResultsBySessionId(ctx, op.Id)
	if repliedToKeeper {
		return nil, ""
	}
	tx, asset := node.buildKeeperTransaction(ctx, op, out)
	if asset != "" {
		return nil, asset
	}
	return []*mtg.Transaction{tx}, ""
}

func (node *Node) readKeyByFingerPath(ctx context.Context, public string) (string, byte, []byte, []byte, error) {
	fingerPath, err := hex.DecodeString(public)
	if err != nil || len(fingerPath) != 12 || fingerPath[8] > 3 {
		return "", 0, nil, nil, fmt.Errorf("node.readKeyByFingerPath(%s) invalid fingerprint", public)
	}
	fingerprint := hex.EncodeToString(fingerPath[:8])
	public, crv, share, err := node.store.ReadKeyByFingerprint(ctx, fingerprint)
	return public, crv, share, fingerPath[8:], err
}

func (node *Node) deriveByPath(_ context.Context, crv byte, share, path []byte) ([]byte, []byte) {
	switch crv {
	case common.CurveSecp256k1ECDSABitcoin, common.CurveSecp256k1ECDSAEthereum:
		conf := cmp.EmptyConfig(curve.Secp256k1{})
		err := conf.UnmarshalBinary(share)
		if err != nil {
			panic(err)
		}
		for i := 0; i < int(path[0]); i++ {
			conf, err = conf.DeriveBIP32(uint32(path[i+1]))
			if err != nil {
				panic(err)
			}
		}
		return common.MarshalPanic(conf.PublicPoint()), conf.ChainKey
	case common.CurveSecp256k1SchnorrBitcoin:
		group := curve.Secp256k1{}
		conf := &frost.TaprootConfig{PrivateShare: group.NewScalar()}
		err := conf.UnmarshalBinary(share)
		if err != nil {
			panic(err)
		}
		return conf.PublicKey, conf.ChainKey
	case common.CurveEdwards25519Default, common.CurveEdwards25519Mixin:
		conf := frost.EmptyConfig(curve.Edwards25519{})
		err := conf.UnmarshalBinary(share)
		if err != nil {
			panic(err)
		}
		return common.MarshalPanic(conf.PublicPoint()), conf.ChainKey
	default:
		panic(crv)
	}
}

func (node *Node) verifySessionHolder(_ context.Context, crv byte, holder string) bool {
	switch crv {
	case common.CurveSecp256k1ECDSABitcoin:
		err := bitcoin.VerifyHolderKey(holder)
		logger.Printf("bitcoin.VerifyHolderKey(%s) => %v", holder, err)
		return err == nil
	case common.CurveSecp256k1ECDSAEthereum:
		err := ethereum.VerifyHolderKey(holder)
		logger.Printf("ethereum.VerifyHolderKey(%s) => %v", holder, err)
		return err == nil
	case common.CurveSecp256k1SchnorrBitcoin:
		var point secp256k1.JacobianPoint
		clipped := point.X.SetByteSlice(common.DecodeHexOrPanic(holder))
		return !clipped
	case common.CurveEdwards25519Mixin,
		common.CurveEdwards25519Default:
		point := curve.Edwards25519Point{}
		err := point.UnmarshalBinary(common.DecodeHexOrPanic(holder))
		return err == nil
	default:
		panic(crv)
	}
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

func (node *Node) verifySessionSignature(ctx context.Context, crv byte, holder string, extra, share, path []byte) (bool, []byte) {
	if !node.checkSignatureAppended(extra) {
		return false, nil
	}
	el := binary.BigEndian.Uint32(extra[:4])
	msg := extra[4 : 4+el]
	sig := extra[4+el:]
	public, _ := node.deriveByPath(ctx, crv, share, path)

	switch crv {
	case common.CurveSecp256k1ECDSABitcoin:
		err := bitcoin.VerifySignatureDER(hex.EncodeToString(public), msg, sig)
		logger.Printf("bitcoin.VerifySignatureDER(%x, %x, %x) => %v", public, msg, sig, err)
		return err == nil, sig
	case common.CurveSecp256k1ECDSAEthereum:
		err := ethereum.VerifyHashSignature(hex.EncodeToString(public), msg, sig)
		logger.Printf("ethereum.VerifyHashSignature(%x, %x, %x) => %v", public, msg, sig, err)
		return err == nil, sig
	case common.CurveEdwards25519Mixin:
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
	case common.CurveEdwards25519Default,
		common.CurveSecp256k1SchnorrBitcoin:
		return common.CheckTestEnvironment(ctx), sig // TODO
	default:
		panic(crv)
	}
}

func (node *Node) verifySessionSignerResults(_ context.Context, session *Session, sessionSigners map[string]string) (bool, []byte) {
	members := node.GetMembers()
	switch session.Operation {
	case common.OperationTypeKeygenInput:
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

	b := common.AESDecrypt(node.aesKey[:], memo)
	req, err := common.DecodeOperation(b)
	if err != nil {
		return nil, fmt.Errorf("common.DecodeOperation(%x) => %v", b, err)
	}

	switch req.Type {
	case common.OperationTypeKeygenInput:
	case common.OperationTypeSignInput:
	default:
		return nil, fmt.Errorf("invalid action %d", req.Type)
	}
	return req, nil
}

func (node *Node) startOperation(ctx context.Context, op *common.Operation, members []party.ID) error {
	logger.Printf("node.startOperation(%v)", op)

	switch op.Type {
	case common.OperationTypeKeygenInput:
		return node.startKeygen(ctx, op)
	case common.OperationTypeSignInput:
		return node.startSign(ctx, op, members)
	default:
		panic(op.Id)
	}
}

func (node *Node) startKeygen(ctx context.Context, op *common.Operation) error {
	logger.Printf("node.startKeygen(%v)", op)
	var err error
	var res *KeygenResult
	switch op.Curve {
	case common.CurveSecp256k1ECDSABitcoin, common.CurveSecp256k1ECDSAEthereum:
		res, err = node.cmpKeygen(ctx, op.IdBytes(), op.Curve)
		logger.Printf("node.cmpKeygen(%v) => %v", op, err)
	case common.CurveSecp256k1SchnorrBitcoin:
		res, err = node.taprootKeygen(ctx, op.IdBytes())
		logger.Printf("node.taprootKeygen(%v) => %v", op, err)
	case common.CurveEdwards25519Mixin, common.CurveEdwards25519Default:
		res, err = node.frostKeygen(ctx, op.IdBytes(), curve.Edwards25519{})
		logger.Printf("node.frostKeygen(%v) => %v", op, err)
	default:
		panic(op.Id)
	}

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
	return node.store.WriteKeyIfNotExists(ctx, op.Id, op.Curve, op.Public, res.Share, saved)
}

func (node *Node) startSign(ctx context.Context, op *common.Operation, members []party.ID) error {
	logger.Printf("node.startSign(%v, %v)\n", op, members)
	if !slices.Contains(members, node.id) {
		logger.Printf("node.startSign(%v, %v) exit without committement\n", op, members)
		return nil
	}
	public, crv, share, path, err := node.readKeyByFingerPath(ctx, op.Public)
	logger.Printf("node.readKeyByFingerPath(%s) => %s %v", op.Public, public, err)
	if err != nil {
		return fmt.Errorf("node.readKeyByFingerPath(%s) => %v", op.Public, err)
	}
	if public == "" {
		return node.store.FailSession(ctx, op.Id)
	}
	if crv != op.Curve {
		return fmt.Errorf("node.startSign(%v) invalid curve %d %d", op, crv, op.Curve)
	}
	fingerprint := op.Public[:16]
	if hex.EncodeToString(common.Fingerprint(public)) != fingerprint {
		return fmt.Errorf("node.startSign(%v) invalid sum %x %s", op, common.Fingerprint(public), fingerprint)
	}

	var res *SignResult
	switch op.Curve {
	case common.CurveSecp256k1ECDSABitcoin, common.CurveSecp256k1ECDSAEthereum:
		res, err = node.cmpSign(ctx, members, public, share, op.Extra, op.IdBytes(), op.Curve, path)
		logger.Printf("node.cmpSign(%v) => %v %v", op, res, err)
	case common.CurveSecp256k1SchnorrBitcoin:
		res, err = node.taprootSign(ctx, members, public, share, op.Extra, op.IdBytes())
		logger.Printf("node.taprootSign(%v) => %v %v", op, res, err)
	case common.CurveEdwards25519Default:
		res, err = node.frostSign(ctx, members, public, share, op.Extra, op.IdBytes(), curve.Edwards25519{}, sign.ProtocolEd25519SHA512)
		logger.Printf("node.frostSign(%v) => %v %v", op, res, err)
	case common.CurveEdwards25519Mixin:
		res, err = node.frostSign(ctx, members, public, share, op.Extra, op.IdBytes(), curve.Edwards25519{}, sign.ProtocolMixinPublic)
		logger.Printf("node.frostSign(%v) => %v %v", op, res, err)
	default:
		panic(op.Id)
	}

	if err != nil {
		err = node.store.FailSession(ctx, op.Id)
		logger.Printf("store.FailSession(%s, startSign) => %v", op.Id, err)
		return err
	}
	extra := node.concatMessageAndSignature(op.Extra, res.Signature)
	err = node.store.MarkSessionPending(ctx, op.Id, op.Curve, op.Public, extra)
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
	b := common.AESDecrypt(node.aesKey[:], m)
	op, err := common.DecodeOperation(b)
	if err != nil {
		return nil, fmt.Errorf("common.DecodeOperation(%x) => %v", b, err)
	}

	switch op.Type {
	case common.OperationTypeSignInput:
	case common.OperationTypeKeygenInput:
	default:
		return nil, fmt.Errorf("invalid action %d", op.Type)
	}

	switch op.Curve {
	case common.CurveSecp256k1ECDSABitcoin, common.CurveSecp256k1ECDSAEthereum:
	case common.CurveSecp256k1SchnorrBitcoin:
	case common.CurveEdwards25519Mixin, common.CurveEdwards25519Default:
	default:
		return nil, fmt.Errorf("invalid curve %d", op.Curve)
	}
	return op, nil
}

func (node *Node) encryptOperation(op *common.Operation) []byte {
	extra := op.Encode()
	if len(extra) > OperationExtraLimit {
		panic(hex.EncodeToString(extra))
	}
	return common.AESEncrypt(node.aesKey[:], extra, op.Id)
}

func (node *Node) buildKeeperTransaction(ctx context.Context, op *common.Operation, act *mtg.Action) (*mtg.Transaction, string) {
	extra := node.encryptOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.buildKeeperTransaction(%v) omitted %x", op, extra))
	}

	amount := decimal.NewFromInt(1)
	if !common.CheckTestEnvironment(ctx) {
		balance := act.CheckAssetBalanceAt(ctx, node.conf.KeeperAssetId)
		if balance.Cmp(amount) < 0 {
			return nil, node.conf.KeeperAssetId
		}
	}

	members := node.GetKeepers()
	threshold := node.keeper.Genesis.Threshold
	traceId := common.UniqueId(node.group.GenesisId(), op.Id)
	tx := act.BuildTransaction(ctx, traceId, node.conf.KeeperAppId, node.conf.KeeperAssetId, amount.String(), string(extra), members, threshold)
	logger.Printf("node.buildKeeperTransaction(%v) => %s %x %x", op, traceId, extra, tx.Serialize())
	return tx, ""
}
