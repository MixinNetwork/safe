package signer

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
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
	switch out.AssetId {
	case node.conf.KeeperAssetId:
		if out.Amount.Cmp(decimal.NewFromInt(1)) < 0 {
			panic(out.TransactionHash)
		}
		op, err := node.parseOperation(ctx, out.Extra)
		logger.Printf("node.parseOperation(%v) => %v %v", out, op, err)
		if err != nil {
			return nil, ""
		}
		err = node.verifyKernelTransaction(ctx, out)
		if err != nil {
			panic(err)
		}
		err = node.tryToFetchMessageForMixin(ctx, op, out)
		if err != nil {
			panic(err)
		}
		needsCommittment := op.Type == common.OperationTypeSignInput
		hash, err := crypto.HashFromString(out.TransactionHash)
		if err != nil {
			panic(err)
		}
		err = node.store.WriteSessionIfNotExist(ctx, op, hash, out.OutputIndex, out.CreatedAt, needsCommittment)
		if err != nil {
			panic(err)
		}
	case node.conf.AssetId:
		senders := strings.Split(out.Senders, ",")
		if len(senders) != 1 || node.findMember(senders[0]) < 0 {
			logger.Printf("invalid senders: %s", out.Senders)
			return nil, ""
		}
		req, err := node.parseSignerMessage(out)
		logger.Printf("node.parseSignerMessage(%v) => %v %v", out, req, err)
		if err != nil {
			return nil, ""
		}
		if string(req.Extra) == PrepareExtra {
			err = node.processSignerPrepare(ctx, req, out)
			logger.Printf("node.processSignerPrepare(%v, %v) => %v", req, out, err)
			if err != nil {
				panic(err)
			}
		} else {
			ts, asset, err := node.processSignerResult(ctx, req, out)
			logger.Printf("node.processSignerResult(%v, %v) => %v %s %v", req, out, ts, asset, err)
			if err != nil {
				panic(err)
			}
			return ts, asset
		}
	}
	return nil, ""
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
	err = node.store.PrepareSessionSignerIfNotExist(ctx, op.Id, out.Senders, out.CreatedAt)
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
	err = node.store.MarkSessionPrepared(ctx, op.Id, out.CreatedAt)
	logger.Printf("node.MarkSessionPrepared(%v) => %v", op, err)
	return err
}

func (node *Node) processSignerResult(ctx context.Context, op *common.Operation, out *mtg.Action) ([]*mtg.Transaction, string, error) {
	session, err := node.store.ReadSession(ctx, op.Id)
	if err != nil {
		return nil, "", fmt.Errorf("store.ReadSession(%s) => %v %v", op.Id, session, err)
	}
	if op.Curve != session.Curve || op.Type != session.Operation {
		panic(session.Id)
	}

	senders := strings.Split(out.Senders, ",")
	self := len(senders) == 1 && senders[0] == string(node.id)
	switch session.Operation {
	case common.OperationTypeKeygenInput:
		err = node.store.WriteSessionSignerIfNotExist(ctx, op.Id, out.Senders, op.Extra, out.CreatedAt, self)
		if err != nil {
			return nil, "", fmt.Errorf("store.WriteSessionSignerIfNotExist(%v) => %v", op, err)
		}
	case common.OperationTypeSignInput:
		err = node.store.UpdateSessionSigner(ctx, op.Id, out.Senders, op.Extra, out.CreatedAt, self)
		if err != nil {
			return nil, "", fmt.Errorf("store.UpdateSessionSigner(%v) => %v", op, err)
		}
	}

	signers, err := node.store.ListSessionSignerResults(ctx, op.Id)
	if err != nil {
		return nil, "", fmt.Errorf("store.ListSessionSignerResults(%s) => %d %v", op.Id, len(signers), err)
	}
	finished, sig := node.verifySessionSignerResults(ctx, session, signers)
	logger.Printf("node.verifySessionSignerResults(%v, %d) => %t %x", session, len(signers), finished, sig)
	if !finished {
		return nil, "", nil
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
			return nil, "", nil
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
		if session.State == common.RequestStateInitial && session.PreparedAt.Valid {
			op := session.asOperation()
			extra := node.concatMessageAndSignature(op.Extra, sig)
			err = node.store.MarkSessionPending(ctx, op.Id, op.Curve, op.Public, extra)
			logger.Printf("store.MarkSessionPending(%v, processSignerResult) => %x %v\n", op, extra, err)
			if err != nil {
				panic(err)
			}
		}

		holder, crv, share, path, err := node.readKeyByFingerPath(ctx, session.Public)
		logger.Printf("node.readKeyByFingerPath(%s) => %s %v", session.Public, holder, err)
		if err != nil {
			return nil, "", err
		}
		if crv != op.Curve {
			return nil, "", nil
		}
		valid, sig := node.verifySessionSignature(ctx, session.Curve, holder, common.DecodeHexOrPanic(session.Extra), share, path)
		logger.Printf("node.verifySessionSignature(%v, %s, %v) => %t", session, holder, path, valid)
		if !valid {
			return nil, "", nil
		}
		op.Type = common.OperationTypeSignOutput
		op.Public = holder
		op.Extra = sig
	default:
		panic(session.Id)
	}

	tx, asset, err := node.buildKeeperTransaction(ctx, op, out.Sequence)
	if err != nil || asset != "" {
		return nil, asset, err
	}
	return []*mtg.Transaction{tx}, "", nil
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

func (node *Node) deriveByPath(ctx context.Context, crv byte, share, path []byte) ([]byte, []byte) {
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

func (node *Node) verifySessionHolder(ctx context.Context, crv byte, holder string) bool {
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
	extra := binary.BigEndian.AppendUint32(nil, uint32(len(msg)))
	extra = append(extra, msg...)
	extra = append(extra, sig...)
	return extra
}

func (node *Node) verifySessionSignature(ctx context.Context, crv byte, holder string, extra, share, path []byte) (bool, []byte) {
	el := binary.BigEndian.Uint32(extra[:4])
	if len(extra) < int(el)+32 {
		return false, nil
	}
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

func (node *Node) verifySessionSignerResults(ctx context.Context, session *Session, sessionSigners map[string]string) (bool, []byte) {
	switch session.Operation {
	case common.OperationTypeKeygenInput:
		var signed int
		for _, id := range node.conf.MTG.Genesis.Members {
			public, found := sessionSigners[id]
			if found && public == session.Public && public == sessionSigners[string(node.id)] {
				signed = signed + 1
			}
		}
		return signed >= len(node.conf.MTG.Genesis.Members), nil
	case common.OperationTypeSignInput:
		var signed int
		var sig []byte
		for _, id := range node.conf.MTG.Genesis.Members {
			extra, found := sessionSigners[id]
			if sig == nil && found {
				sig = common.DecodeHexOrPanic(extra)
			}
			if found && extra != "" && hex.EncodeToString(sig) == extra {
				signed = signed + 1
			}
		}
		return signed > node.threshold, sig
	default:
		panic(session.Id)
	}
}

func (node *Node) parseSignerMessage(out *mtg.Action) (*common.Operation, error) {
	_, _, memo := mtg.DecodeMixinExtra(out.Extra)

	b := common.AESDecrypt(node.aesKey[:], []byte(memo))
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
	err = node.sendKeygenBackup(ctx, op, res.Share)
	logger.Printf("node.sendKeygenBackup(%v, %d) => %v", op, len(res.Share), err)
	if err != nil {
		err = node.store.FailSession(ctx, op.Id)
		logger.Printf("store.FailSession(%s, startKeygen) => %v", op.Id, err)
		return err
	}
	return node.store.WriteKeyIfNotExists(ctx, op.Id, op.Curve, op.Public, res.Share)
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

func (node *Node) tryToFetchMessageForMixin(ctx context.Context, op *common.Operation, out *mtg.Action) error {
	if op.Curve != common.CurveEdwards25519Mixin {
		return nil
	}
	if op.Type != common.OperationTypeSignInput {
		return nil
	}
	if len(op.Extra) != 64 {
		return nil
	}
	hash, err := crypto.HashFromString(out.TransactionHash)
	if err != nil {
		panic(err)
	}
	refs := node.readKernelTransactionReferences(ctx, hash)
	if len(refs) != 1 || !bytes.Equal(refs[0][:], op.Extra[32:]) {
		return nil
	}

	// mask || storage-reference
	ref := refs[0]
	op.Extra = append(op.Extra[:32], ref[:]...)
	return nil
}

func (node *Node) readKernelStorageOrPanic(ctx context.Context, stx crypto.Hash) []byte {
	if common.CheckTestEnvironment(ctx) {
		k := hex.EncodeToString(stx[:])
		o, err := node.store.ReadProperty(ctx, k)
		if err != nil {
			panic(err)
		}
		v, err := hex.DecodeString(o)
		if err != nil {
			panic(err)
		}
		data, err := common.Base91Decode(string(v))
		if err != nil || len(data) < 32 {
			panic(stx.String())
		}
		return data
	}

	tx, err := common.ReadKernelTransaction(node.conf.MixinRPC, stx)
	if err != nil {
		panic(stx.String())
	}
	g, t, m := mtg.DecodeMixinExtra(string(tx.Extra))
	if g == "" && t == "" && m == "" {
		panic(stx.String())
	}
	data, err := common.Base91Decode(m)
	if err != nil || len(data) < 32 {
		panic(stx.String())
	}
	return data
}

func (node *Node) readKernelTransactionReferences(ctx context.Context, hash crypto.Hash) []crypto.Hash {
	if common.CheckTestEnvironment(ctx) {
		k := hex.EncodeToString(hash[:])
		o, err := node.store.ReadProperty(ctx, k)
		if err != nil {
			panic(err)
		}
		v, err := hex.DecodeString(o)
		if err != nil {
			panic(err)
		}
		var ref crypto.Hash
		if len(v) == 0 {
			return nil
		}
		if len(v) != len(ref) {
			panic(o)
		}
		copy(ref[:], v)
		return []crypto.Hash{ref}
	}

	tx, err := common.ReadKernelTransaction(node.conf.MixinRPC, hash)
	if err != nil {
		panic(hash.String())
	}
	return tx.References
}

func (node *Node) verifyKernelTransaction(ctx context.Context, out *mtg.Action) error {
	if common.CheckTestEnvironment(ctx) {
		return nil
	}

	return common.VerifyKernelTransaction(node.conf.MixinRPC, out, KernelTimeout)
}

func (node *Node) parseOperation(ctx context.Context, memo string) (*common.Operation, error) {
	g, t, m := mtg.DecodeMixinExtra(memo)
	if g == "" && t == "" && m == "" {
		return nil, fmt.Errorf("mtg.DecodeMixinExtra(%s)", memo)
	}
	b := common.AESDecrypt(node.aesKey[:], []byte(m))
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

func (node *Node) buildKeeperTransaction(ctx context.Context, op *common.Operation, sequence uint64) (*mtg.Transaction, string, error) {
	extra := node.encryptOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.buildKeeperTransaction(%v) omitted %x", op, extra))
	}

	if !common.CheckTestEnvironment(ctx) {
		balance, err := node.group.CheckAssetBalanceAt(ctx, node.conf.AppId, node.conf.KeeperAssetId, sequence)
		if err != nil {
			return nil, "", err
		}
		if balance.Cmp(decimal.NewFromInt(1)) < 0 {
			return nil, node.conf.KeeperAssetId, nil
		}
	}

	members := node.keeper.Genesis.Members
	threshold := node.keeper.Genesis.Threshold
	traceId := common.UniqueId(node.group.GenesisId(), op.Id)
	tx := node.group.BuildTransaction(traceId, node.conf.AppId, node.conf.KeeperAppId, node.conf.KeeperAssetId, "1", string(extra), members, threshold, sequence)
	logger.Printf("node.buildKeeperTransaction(%v) => %s %x", op, traceId, extra)
	return tx, "", nil
}
