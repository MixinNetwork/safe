package keeper

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

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

// TODO encrypt with observer aes key
func (node *Node) writeToMVMOrPanic(ctx context.Context, extra []byte) []byte {
	logger.Printf("node.writeToMVMOrPanic(%x)", extra)
	if common.CheckTestEnvironment(ctx) {
		key := common.MVMHash(extra)
		k := hex.EncodeToString(key)
		v := hex.EncodeToString(extra)
		err := node.store.WriteProperty(ctx, k, v)
		if err != nil {
			panic(err)
		}
		return key
	}

	for start := time.Now(); ; {
		k, err := node.mvmWrite(ctx, extra, start)
		logger.Printf("common.MVMStorageWrite(%x) => %x %v", extra, k, err)
		if err != nil && start.Add(time.Minute).After(time.Now()) {
			time.Sleep(3 * time.Second)
			continue
		} else if err != nil || len(k) == 0 {
			panic(err)
		} else {
			return k
		}
	}
}

func (node *Node) mvmWrite(ctx context.Context, extra []byte, at time.Time) ([]byte, error) {
	if time.Now().Hour()%len(node.conf.MTG.Genesis.Members) == node.Index() || at.Add(time.Minute).Before(time.Now()) {
		return common.MVMStorageWrite(node.conf.MVMRPC, node.conf.MVMKey, extra)
	}
	key := common.MVMHash(extra)
	val, err := common.MVMStorageRead(node.conf.MVMRPC, key)
	if err != nil || !bytes.Equal(val, extra) {
		return nil, fmt.Errorf("mvmWrite(%x) => %v", val, err)
	}
	return key, nil
}
