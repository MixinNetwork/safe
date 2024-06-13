package keeper

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/shopspring/decimal"
)

func (node *Node) parseRequest(out *mtg.Action) (*common.Request, error) {
	switch out.AssetId {
	case node.conf.AssetId:
		if out.Amount.Cmp(decimal.NewFromInt(1)) < 0 {
			panic(out.TransactionHash)
		}
		return node.parseSignerResponse(out)
	case node.conf.ObserverAssetId:
		if out.Amount.Cmp(decimal.NewFromInt(1)) < 0 {
			panic(out.TransactionHash)
		}
		return node.parseObserverRequest(out)
	default:
		return node.parseHolderRequest(out)
	}
}

func (node *Node) requestRole(assetId string) uint8 {
	switch assetId {
	case node.conf.AssetId:
		return common.RequestRoleSigner
	case node.conf.ObserverAssetId:
		return common.RequestRoleObserver
	default:
		return common.RequestRoleHolder
	}
}

func (node *Node) parseObserverRequest(out *mtg.Action) (*common.Request, error) {
	senders := strings.Split(out.Senders, ",")
	if len(senders) != 1 && senders[0] != node.conf.ObserverUserId {
		return nil, fmt.Errorf("parseObserverRequest(%v) %s", out, node.conf.ObserverUserId)
	}
	_, _, m := mtg.DecodeMixinExtra(out.Extra)
	b := common.AESDecrypt(node.observerAESKey[:], []byte(m))
	role := node.requestRole(out.AssetId)
	return common.DecodeRequest(out, b, role)
}

func (node *Node) parseSignerResponse(out *mtg.Action) (*common.Request, error) {
	g, t, m := mtg.DecodeMixinExtra(out.Extra)
	if g == "" && t == "" && m == "" {
		return nil, fmt.Errorf("node.parseSignerResponse(%v)", out)
	}
	b := common.AESDecrypt(node.signerAESKey[:], []byte(m))
	role := node.requestRole(out.AssetId)
	return common.DecodeRequest(out, b, role)
}

func (node *Node) parseHolderRequest(out *mtg.Action) (*common.Request, error) {
	g, t, m := mtg.DecodeMixinExtra(out.Extra)
	if g == "" && t == "" && m == "" {
		return nil, fmt.Errorf("node.parseHolderRequest(%v)", out)
	}
	role := node.requestRole(out.AssetId)
	return common.DecodeRequest(out, []byte(m), role)
}

func (node *Node) readStorageExtraFromObserver(ctx context.Context, ref crypto.Hash) []byte {
	if common.CheckTestEnvironment(ctx) {
		val, err := node.store.ReadProperty(ctx, ref.String())
		if err != nil {
			panic(ref.String())
		}
		raw, err := base64.RawURLEncoding.DecodeString(val)
		if err != nil {
			panic(ref.String())
		}
		return raw
	}

	ver, err := common.ReadKernelTransaction(node.conf.MixinRPC, ref)
	if err != nil {
		panic(ref.String())
	}

	raw := common.AESDecrypt(node.observerAESKey[:], ver.Extra)
	return raw[16:]
}

func (node *Node) writeStorageTransaction(ctx context.Context, sequence uint64, extra []byte) (*mtg.Transaction, error) {
	logger.Printf("node.writeStorageTransaction(%x)", extra)
	if common.CheckTestEnvironment(ctx) {
		sTraceId := crypto.Blake3Hash(extra).String()
		sTraceId = mtg.UniqueId(sTraceId, sTraceId)
		hash := crypto.Blake3Hash(extra)
		tx := &mtg.Transaction{
			TraceId: sTraceId,
			Hash:    hash,
		}

		k := hex.EncodeToString(hash[:])
		v := hex.EncodeToString(extra)
		o, err := node.store.ReadProperty(ctx, k)
		if err != nil {
			panic(err)
		}
		if o == v {
			return tx, nil
		}
		err = node.store.WriteProperty(ctx, k, v)
		if err != nil {
			panic(err)
		}
		return tx, nil
	}

	stx, err := node.group.BuildStorageTransaction(ctx, node.conf.AppId, extra, sequence)
	logger.Printf("group.BuildStorageTransaction(%x) => %v %v", extra, stx, err)
	return stx, err
}
