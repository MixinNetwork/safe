package keeper

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
)

const (
	SignerKeygenMaximum = 128
)

func (node *Node) sendSignerKeygenRequest(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string, error) {
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

	batch, ok := new(big.Int).SetString(req.Extra, 16)
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
		tx, asset, err := node.buildSignerTransaction(ctx, req.Sequence, op)
		if err != nil || asset != "" {
			return nil, asset, err
		}
		ts = append(ts, tx)
	}

	return ts, "", node.store.FailRequest(ctx, req.Id)
}

func (node *Node) sendSignerSignRequest(ctx context.Context, request *common.Request, req *store.SignatureRequest, path string) (*mtg.Transaction, string, error) {
	crv := common.NormalizeCurve(req.Curve)
	switch crv {
	case common.CurveSecp256k1ECDSABitcoin:
	case common.CurveSecp256k1ECDSAEthereum:
	default:
		panic(req.Curve)
	}

	fp := common.DecodeHexOrPanic(path)
	if len(fp) != 4 {
		panic(path)
	}
	fingerPath := append(common.Fingerprint(req.Signer), fp...)
	op := &common.Operation{
		Id:     req.RequestId,
		Type:   common.OperationTypeSignInput,
		Curve:  crv,
		Public: hex.EncodeToString(fingerPath),
		Extra:  common.DecodeHexOrPanic(req.Message),
	}
	return node.buildSignerTransaction(ctx, request.Sequence, op)
}

func (node *Node) encryptSignerOperation(op *common.Operation) []byte {
	extra := op.Encode()
	return common.AESEncrypt(node.signerAESKey[:], extra, op.Id)
}

func (node *Node) buildSignerTransaction(ctx context.Context, sequence uint64, op *common.Operation) (*mtg.Transaction, string, error) {
	extra := node.encryptSignerOperation(op)
	if len(extra) > 160 {
		panic(fmt.Errorf("node.buildSignerTransaction(%v) omitted %x", op, extra))
	}
	members := node.signer.Genesis.Members
	threshold := node.signer.Genesis.Threshold
	tx, asset, err := node.buildTransaction(ctx, sequence, node.conf.AssetId, members, threshold, "1", extra, op.Id)
	logger.Printf("node.buildSignerTransaction(%v %s %x) => %v %s %v", op, op.Id, extra, tx, asset, err)
	return tx, asset, err
}
