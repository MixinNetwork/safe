package keeper

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/mtg"
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
	if len(out.Senders) != 1 && out.Senders[0] != node.conf.ObserverUserId {
		return nil, fmt.Errorf("parseObserverRequest(%v) %s", out, node.conf.ObserverUserId)
	}
	a, m := mtg.DecodeMixinExtraHEX(out.Extra)
	if a != node.conf.AppId {
		panic(out.Extra)
	}
	if len(m) < 12 {
		return nil, fmt.Errorf("node.parseObserverRequest(%v)", out)
	}
	b := common.AESDecrypt(node.observerAESKey[:], m)
	role := node.requestRole(out.AssetId)
	return common.DecodeRequest(out, b, role)
}

func (node *Node) parseSignerResponse(out *mtg.Action) (*common.Request, error) {
	a, m := mtg.DecodeMixinExtraHEX(out.Extra)
	if a != node.conf.AppId {
		panic(out.Extra)
	}
	if len(m) < 12 {
		return nil, fmt.Errorf("node.parseSignerResponse(%v)", out)
	}
	b := common.AESDecrypt(node.signerAESKey[:], m)
	role := node.requestRole(out.AssetId)
	return common.DecodeRequest(out, b, role)
}

func (node *Node) parseHolderRequest(out *mtg.Action) (*common.Request, error) {
	a, m := mtg.DecodeMixinExtraHEX(out.Extra)
	if a != node.conf.AppId {
		panic(out.Extra)
	}
	if m == nil {
		return nil, fmt.Errorf("node.parseHolderRequest(%v)", out)
	}
	role := node.requestRole(out.AssetId)
	return common.DecodeRequest(out, m, role)
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

	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, ref.String())
	if err != nil {
		panic(ref.String())
	}

	raw := common.AESDecrypt(node.observerAESKey[:], ver.Extra)
	return raw[16:]
}

func (node *Node) buildStorageTransaction(ctx context.Context, req *common.Request, extra []byte) *mtg.Transaction {
	logger.Printf("node.writeStorageTransaction(%x)", extra)
	if common.CheckTestEnvironment(ctx) {
		tx := req.Output.BuildStorageTransaction(ctx, extra)
		v := hex.EncodeToString(extra)
		o, err := node.store.ReadProperty(ctx, tx.TraceId)
		if err != nil {
			panic(err)
		}
		if o == v {
			return tx
		}
		err = node.store.WriteProperty(ctx, tx.TraceId, v)
		if err != nil {
			panic(err)
		}
		return tx
	}

	enough := req.Output.CheckAssetBalanceForStorageAt(ctx, extra)
	if !enough {
		return nil
	}
	stx := req.Output.BuildStorageTransaction(ctx, extra)
	logger.Printf("group.BuildStorageTransaction(%x) => %v", extra, stx)
	return stx
}
