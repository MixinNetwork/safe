package signer

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost/sign"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/fox-one/mixin-sdk-go"
)

const (
	OperationExtraLimit  = 128
	MPCFirstMessageRound = 2
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

func (node *Node) ProcessOutput(ctx context.Context, out *mtg.Output) {
	switch {
	case out.AssetID == node.conf.KeeperAssetId:
		op, err := node.parseOperation(ctx, out.Memo)
		logger.Printf("node.parseOperation(%v) => %v %v", out, op, err)
		if err != nil {
			return
		}
		err = node.verifyKernelTransaction(ctx, out)
		if err != nil {
			panic(err)
		}
		if len(op.Extra) == 32 && op.Curve == common.CurveEdwards25519Mixin && op.Type == common.OperationTypeSignInput {
			op.Extra = node.readKernelStorageOrPanic(ctx, op)
		}
		err = node.store.WriteSessionIfNotExist(ctx, op, out.TransactionHash, out.OutputIndex, out.CreatedAt)
		if err != nil {
			panic(err)
		}
	case node.findMember(out.Sender) >= 0:
		req, err := node.parseSignerResult(out)
		logger.Printf("node.parseSignerResult(%v) => %v %v", out, req, err)
		if err != nil {
			return
		}
		err = node.processSignerResult(ctx, req, out)
		logger.Printf("node.processSignerResult(%v, %v) => %v", req, out, err)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) ProcessCollectibleOutput(context.Context, *mtg.CollectibleOutput) {}

func (node *Node) processSignerResult(ctx context.Context, op *common.Operation, out *mtg.Output) error {
	session, err := node.store.ReadSession(ctx, op.Id)
	if err != nil {
		return fmt.Errorf("store.ReadSession(%s) => %v %v", op.Id, session, err)
	}
	if op.Curve != session.Curve || op.Type != session.Operation {
		panic(session.Id)
	}

	self := out.Sender == string(node.id)
	err = node.store.WriteSessionSignerIfNotExist(ctx, op.Id, out.Sender, op.Extra, out.CreatedAt, self)
	if err != nil {
		return fmt.Errorf("store.WriteSessionSignerIfNotExist(%v) => %v", op, err)
	}
	signers, err := node.store.ListSessionSigners(ctx, op.Id)
	if err != nil {
		return fmt.Errorf("store.ListSessionSigners(%s) => %d %v", op.Id, len(signers), err)
	}

	finished := node.verifySessionSigners(session, signers)
	if !finished {
		return nil
	}
	if l := len(signers); l < node.threshold || l < node.conf.MTG.Genesis.Threshold {
		panic(session.Id)
	}

	op = &common.Operation{Id: op.Id, Curve: session.Curve}
	switch session.Operation {
	case common.OperationTypeKeygenInput:
		if signers[string(node.id)] != session.Public {
			panic(session.Public)
		}
		valid := node.verifySessionHolder(ctx, session.Curve, session.Public)
		logger.Printf("node.verifySessionHolder(%d, %s) => %t", session.Curve, session.Public, valid)
		if !valid {
			return nil
		}
		op.Type = common.OperationTypeKeygenOutput
		op.Extra = []byte{common.RequestRoleSigner}
		op.Public = session.Public
	case common.OperationTypeSignInput:
		if sig := signers[string(node.id)]; sig == "" || !strings.HasSuffix(session.Extra, sig) {
			panic(session.Extra)
		}
		holder, crv, _, err := node.store.ReadKeyByShortSum(ctx, session.Public)
		logger.Printf("store.ReadKeyByShortSum(%s) => %s %v", session.Public, holder, err)
		if err != nil {
			return err
		}
		if crv != op.Curve {
			return nil
		}
		valid, sig := node.verifySessionSignature(ctx, session.Curve, holder, common.DecodeHexOrPanic(session.Extra))
		logger.Printf("node.verifySessionSignature(%d, %s) => %t", session.Curve, holder, valid)
		if !valid {
			return nil
		}
		op.Type = common.OperationTypeSignOutput
		op.Public = holder
		op.Extra = sig
	default:
		panic(session.Id)
	}

	err = node.verifyKernelTransaction(ctx, out)
	if err != nil {
		return err
	}
	return node.buildKeeperTransaction(ctx, op)
}

func (node *Node) verifySessionHolder(ctx context.Context, crv byte, holder string) bool {
	switch crv {
	case common.CurveSecp256k1ECDSABitcoin,
		common.CurveSecp256k1ECDSAEthereum:
		err := bitcoin.VerifyHolderKey(holder)
		logger.Printf("node.verifySessionHolder(%d, %s) => %v", crv, holder, err)
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

func (node *Node) verifySessionSignature(ctx context.Context, crv byte, holder string, extra []byte) (bool, []byte) {
	if len(extra) < int(extra[0])+32 {
		return false, nil
	}
	msg := extra[1 : 1+extra[0]]
	sig := extra[1+extra[0]:]
	switch crv {
	case common.CurveSecp256k1ECDSABitcoin:
		err := bitcoin.VerifySignatureDER(holder, msg, sig)
		logger.Printf("node.verifySessionSignature(%d, %s, %x) => %v", crv, holder, extra, err)
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
		res := mpub.Verify(msg[32:], msig)
		logger.Printf("node.verifySessionSignature(%d, %s, %x) => %t", crv, holder, extra, res)
		return res, sig
	case common.CurveEdwards25519Default,
		common.CurveSecp256k1ECDSAEthereum,
		common.CurveSecp256k1SchnorrBitcoin:
		return common.CheckTestEnvironment(ctx), sig // TODO
	default:
		panic(crv)
	}
}

func (node *Node) verifySessionSigners(session *Session, sessionSigners map[string]string) bool {
	// TODO do more robust checks, allow some signer fails
	switch session.Operation {
	case common.OperationTypeKeygenInput:
		for _, id := range node.conf.MTG.Genesis.Members {
			public, found := sessionSigners[id]
			if !found || public != session.Public || public != sessionSigners[string(node.id)] {
				return false
			}
		}
		return true
	case common.OperationTypeSignInput:
		for _, id := range node.conf.MTG.Genesis.Members {
			extra, found := sessionSigners[id]
			if !found || extra == "" || extra != sessionSigners[string(node.id)] {
				return false
			}
		}
		return true
	default:
		panic(session.Id)
	}
}

func (node *Node) parseSignerResult(out *mtg.Output) (*common.Operation, error) {
	b, err := common.Base91Decode(out.Memo)
	if err != nil {
		return nil, fmt.Errorf("common.Base91Decode(%s) => %v", out.Memo, err)
	}

	b = common.AESDecrypt(node.aesKey[:], b)
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

func (node *Node) startOperation(ctx context.Context, op *common.Operation) error {
	logger.Printf("node.startOperation(%v)", op)

	switch op.Type {
	case common.OperationTypeKeygenInput:
		return node.startKeygen(ctx, op)
	case common.OperationTypeSignInput:
		return node.startSign(ctx, op)
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
		logger.Verbosef("node.cmpKeygen(%v) => %v", op, err)
	case common.CurveSecp256k1SchnorrBitcoin:
		res, err = node.taprootKeygen(ctx, op.IdBytes())
		logger.Verbosef("node.taprootKeygen(%v) => %v", op, err)
	case common.CurveEdwards25519Mixin, common.CurveEdwards25519Default:
		res, err = node.frostKeygen(ctx, op.IdBytes(), curve.Edwards25519{})
		logger.Verbosef("node.frostKeygen(%v) => %v", op, err)
	default:
		panic(op.Id)
	}

	if err != nil {
		return node.store.FailSession(ctx, op.Id)
	}
	op.Public = hex.EncodeToString(res.Public)
	return node.store.WriteKeyIfNotExists(ctx, op.Id, op.Curve, op.Public, res.Share)
}

func (node *Node) startSign(ctx context.Context, op *common.Operation) error {
	logger.Printf("node.startSign(%v)", op)
	public, crv, share, err := node.store.ReadKeyByShortSum(ctx, op.Public)
	logger.Printf("store.ReadKeyByShortSum(%s) => %s %v", op.Public, public, err)
	if err != nil {
		return fmt.Errorf("store.ReadKeyByShortSum(%s) => %v", op.Public, err)
	}
	if public == "" {
		return node.store.FailSession(ctx, op.Id)
	}
	if crv != op.Curve {
		return fmt.Errorf("node.startSign(%v) invalid curve %d %d", op, crv, op.Curve)
	}
	if hex.EncodeToString(common.ShortSum(public)) != op.Public {
		return fmt.Errorf("node.startSign(%v) invalid sum %x %s", op, common.ShortSum(public), op.Public)
	}

	var res *SignResult
	switch op.Curve {
	case common.CurveSecp256k1ECDSABitcoin, common.CurveSecp256k1ECDSAEthereum:
		res, err = node.cmpSign(ctx, public, share, op.Extra, op.IdBytes(), op.Curve)
		logger.Verbosef("node.cmpSign(%v) => %v %v", op, res, err)
	case common.CurveSecp256k1SchnorrBitcoin:
		res, err = node.taprootSign(ctx, public, share, op.Extra, op.IdBytes())
		logger.Verbosef("node.taprootSign(%v) => %v %v", op, res, err)
	case common.CurveEdwards25519Default:
		res, err = node.frostSign(ctx, public, share, op.Extra, op.IdBytes(), curve.Edwards25519{}, sign.ProtocolEd25519SHA512)
		logger.Verbosef("node.frostSign(%v) => %v %v", op, res, err)
	case common.CurveEdwards25519Mixin:
		res, err = node.frostSign(ctx, public, share, op.Extra, op.IdBytes(), curve.Edwards25519{}, sign.ProtocolMixinPublic)
		logger.Verbosef("node.frostSign(%v) => %v %v", op, res, err)
	default:
		panic(op.Id)
	}

	if err != nil {
		return node.store.FailSession(ctx, op.Id)
	}
	extra := []byte{byte(len(op.Extra))}
	extra = append(extra, op.Extra...)
	extra = append(extra, res.Signature...)
	return node.store.FinishSignSession(ctx, op.Id, op.Curve, op.Public, extra)
}

func (node *Node) readKernelStorageOrPanic(ctx context.Context, op *common.Operation) []byte {
	if common.CheckTestEnvironment(ctx) {
		k := hex.EncodeToString(op.Extra)
		o, err := node.store.ReadProperty(ctx, k)
		if err != nil {
			panic(err)
		}
		v, err := hex.DecodeString(o)
		if err != nil {
			panic(err)
		}
		return v
	}

	var stx crypto.Hash
	copy(stx[:], op.Extra)
	tx, err := common.ReadKernelTransaction(node.conf.MixinRPC, stx)
	if err != nil {
		panic(stx.String())
	}
	smsp := mtg.DecodeMixinExtra(string(tx.Extra))
	if smsp == nil {
		panic(stx.String())
	}
	data, err := common.Base91Decode(smsp.M)
	if err != nil || len(data) < 32 {
		panic(op.Id)
	}
	return data
}

func (node *Node) verifyKernelTransaction(ctx context.Context, out *mtg.Output) error {
	if common.CheckTestEnvironment(ctx) {
		return nil
	}

	return common.VerifyKernelTransaction(node.conf.MixinRPC, out, time.Minute)
}

func (node *Node) parseOperation(ctx context.Context, memo string) (*common.Operation, error) {
	msp := mtg.DecodeMixinExtra(memo)
	if msp == nil {
		return nil, fmt.Errorf("mtg.DecodeMixinExtra(%s)", memo)
	}
	b := common.AESDecrypt(node.aesKey[:], []byte(msp.M))
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

func (node *Node) buildKeeperTransaction(ctx context.Context, op *common.Operation) error {
	extra := node.encryptOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.buildKeeperTransaction(%v) omitted %x", op, extra))
	}
	if common.CheckTestEnvironment(ctx) {
		return node.store.WriteProperty(ctx, "KEEPER:"+op.Id, hex.EncodeToString(extra))
	}

	members := node.keeper.Genesis.Members
	threshold := node.keeper.Genesis.Threshold
	traceId := mixin.UniqueConversationID(node.group.GenesisId(), op.Id)
	err := node.group.BuildTransaction(ctx, node.conf.KeeperAssetId, members, threshold, "1", string(extra), traceId, "")
	logger.Printf("node.buildKeeperTransaction(%v) => %s %x %v", op, traceId, extra, err)
	return err
}
