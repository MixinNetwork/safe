package keeper

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
)

const (
	SignerKeygenMaximum = 128
)

func (node *Node) processSignerKeygenRequests(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string, error) {
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
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}

	batch, ok := new(big.Int).SetString(req.ExtraHEX, 16)
	if !ok || batch.Cmp(big.NewInt(1)) < 0 || batch.Cmp(big.NewInt(SignerKeygenMaximum)) > 0 {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	var ts []*mtg.Transaction
	for i := 0; i < int(batch.Int64()); i++ {
		op := &common.Operation{
			Type:  common.OperationTypeKeygenInput,
			Curve: crv,
		}
		op.Id = common.UniqueId(req.Id, fmt.Sprintf("%8d", i))
		op.Id = common.UniqueId(op.Id, fmt.Sprintf("MTG:%v:%d", node.signer.Genesis.Members, node.signer.Genesis.Threshold))
		tx := node.buildSignerTransaction(ctx, req.Sequence, op)
		if tx == nil {
			return nil, node.conf.AssetId, node.store.FailRequest(ctx, req.Id)
		}
		ts = append(ts, tx)
	}

	return ts, "", node.store.FailRequest(ctx, req.Id)
}

func (node *Node) buildSignerSignRequests(ctx context.Context, request *common.Request, srs []*store.SignatureRequest, path string) []*mtg.Transaction {
	var ts []*mtg.Transaction
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
		tx := node.buildSignerTransaction(ctx, request.Sequence, op)
		if tx == nil {
			return nil
		}
		ts = append(ts, tx)
	}
	return ts
}

func (node *Node) encryptSignerOperation(op *common.Operation) []byte {
	extra := op.Encode()
	return common.AESEncrypt(node.signerAESKey[:], extra, op.Id)
}

func (node *Node) buildSignerTransaction(ctx context.Context, sequence uint64, op *common.Operation) *mtg.Transaction {
	extra := node.encryptSignerOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.buildSignerTransaction(%v) omitted %x", op, extra))
	}
	members := node.signer.Genesis.Members
	threshold := node.signer.Genesis.Threshold
	return node.buildTransaction(ctx, sequence, node.conf.SignerAppId, node.conf.AssetId, members, threshold, "1", extra, op.Id)
}
