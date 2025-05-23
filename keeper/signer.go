package keeper

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/safe/mtg"
)

const (
	SignerKeygenMaximum = 128
)

func (node *Node) processSignerKeygenRequests(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != common.ActionObserverRequestSignerKeys {
		panic(req.Action)
	}
	crv := common.NormalizeCurve(req.Curve)
	switch crv {
	case common.CurveSecp256k1ECDSABitcoin:
	case common.CurveSecp256k1ECDSAEthereum:
	default:
		return node.failRequest(ctx, req, "")
	}

	batch, ok := new(big.Int).SetString(req.ExtraHEX, 16)
	if !ok || batch.Cmp(big.NewInt(1)) < 0 || batch.Cmp(big.NewInt(SignerKeygenMaximum)) > 0 {
		return node.failRequest(ctx, req, "")
	}
	signers := node.GetSigners()
	var txs []*mtg.Transaction
	for i := range batch.Int64() {
		op := &common.Operation{
			Type:  common.OperationTypeKeygenInput,
			Curve: crv,
		}
		op.Id = common.UniqueId(req.Id, fmt.Sprintf("%8d", i))
		op.Id = common.UniqueId(op.Id, fmt.Sprintf("MTG:%v:%d", signers, node.signer.Genesis.Threshold))
		tx := node.buildSignerTransaction(ctx, req.Output, op)
		if tx == nil {
			return node.failRequest(ctx, req, "")
		}
		txs = append(txs, tx)
	}

	err := node.store.FailRequest(ctx, req, "", txs)
	if err != nil {
		panic(err)
	}
	return txs, ""
}

func (node *Node) buildSignerSignRequests(ctx context.Context, request *common.Request, srs []*store.SignatureRequest, path string) []*mtg.Transaction {
	var txs []*mtg.Transaction
	for _, sr := range srs {
		crv := common.NormalizeCurve(sr.Curve)
		switch crv {
		case common.CurveSecp256k1ECDSABitcoin:
		case common.CurveSecp256k1ECDSAEthereum:
		default:
			panic(sr.Curve)
		}

		fp := common.DecodeHexOrPanic(path)
		if len(fp) != 4 {
			panic(path)
		}
		fingerPath := append(common.Fingerprint(sr.Signer), fp...)
		op := &common.Operation{
			Id:     sr.RequestId,
			Type:   common.OperationTypeSignInput,
			Curve:  crv,
			Public: hex.EncodeToString(fingerPath),
			Extra:  common.DecodeHexOrPanic(sr.Message),
		}
		tx := node.buildSignerTransaction(ctx, request.Output, op)
		if tx == nil {
			return nil
		}
		txs = append(txs, tx)
	}
	return txs
}

func (node *Node) encryptSignerOperation(op *common.Operation) []byte {
	extra := op.Encode()
	return common.AESEncrypt(node.signerAESKey[:], extra, op.Id)
}

func (node *Node) buildSignerTransaction(ctx context.Context, act *mtg.Action, op *common.Operation) *mtg.Transaction {
	extra := node.encryptSignerOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.buildSignerTransaction(%v) omitted %x", op, extra))
	}
	members := node.GetSigners()
	threshold := node.signer.Genesis.Threshold
	return node.buildTransaction(ctx, act, node.conf.SignerAppId, node.conf.AssetId, members, threshold, "1", extra, op.Id)
}
