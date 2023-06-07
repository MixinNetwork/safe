package keeper

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
)

func (node *Node) parseRequest(out *mtg.Output) (*common.Request, error) {
	switch out.AssetID {
	case node.conf.AssetId:
		return node.parseSignerResponse(out)
	case node.conf.ObserverAssetId:
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

func (node *Node) parseObserverRequest(out *mtg.Output) (*common.Request, error) {
	if out.Sender != node.conf.ObserverUserId {
		return nil, fmt.Errorf("parseObserverRequest(%v) %s", out, node.conf.ObserverUserId)
	}
	b, err := common.Base91Decode(out.Memo)
	if err != nil {
		return nil, err
	}
	b = common.AESDecrypt(node.observerAESKey[:], b)
	role := node.requestRole(out.AssetID)
	return common.DecodeRequest(out, b, role)
}

func (node *Node) parseSignerResponse(out *mtg.Output) (*common.Request, error) {
	msp := mtg.DecodeMixinExtra(out.Memo)
	if msp == nil {
		return nil, fmt.Errorf("node.parseSignerResponse(%v)", out)
	}
	b := common.AESDecrypt(node.signerAESKey[:], []byte(msp.M))
	role := node.requestRole(out.AssetID)
	return common.DecodeRequest(out, b, role)
}

func (node *Node) parseHolderRequest(out *mtg.Output) (*common.Request, error) {
	b, err := base64.RawURLEncoding.DecodeString(out.Memo)
	if err != nil {
		return nil, err
	}
	role := node.requestRole(out.AssetID)
	return common.DecodeRequest(out, b, role)
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
	smsp := mtg.DecodeMixinExtra(string(ver.Extra))
	if smsp == nil {
		panic(ref.String())
	}
	raw, err := base64.RawURLEncoding.DecodeString(smsp.M)
	if err != nil {
		panic(ref.String())
	}
	raw = common.AESDecrypt(node.observerAESKey[:], raw)
	return raw[16:]
}

func (node *Node) writeStorageOrPanic(ctx context.Context, extra []byte) crypto.Hash {
	logger.Printf("node.writeStorageOrPanic(%x)", extra)
	if common.CheckTestEnvironment(ctx) {
		tx := crypto.Blake3Hash(extra)
		k := hex.EncodeToString(tx[:])
		v := hex.EncodeToString(extra)
		o, err := node.store.ReadProperty(ctx, k)
		if err != nil {
			panic(err)
		}
		if o == v {
			return tx
		}
		err = node.store.WriteProperty(ctx, k, v)
		if err != nil {
			panic(err)
		}
		return tx
	}

	for {
		stx, err := node.group.BuildStorageTransaction(ctx, extra, "")
		logger.Printf("group.BuildStorageTransaction(%x) => %v %v", extra, stx, err)
		if err != nil {
			panic(err)
		}
		if stx.Hash.HasValue() && stx.State >= mtg.TransactionStateSigned {
			return stx.Hash
		}
		time.Sleep(time.Second)
	}
}
