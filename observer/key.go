package observer

import (
	"context"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/fox-one/mixin-sdk-go"
)

func (node *Node) bitcoinKeyLoop(ctx context.Context) {
	for {
		err := node.bitcoinRequestSignerKeys(ctx)
		if err != nil {
			panic(err)
		}

		err = node.bitcoinAddObserverKeys(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(10 * time.Minute)
	}
}

func (node *Node) bitcoinAddObserverKeys(ctx context.Context) error {
	count, err := node.keeperStore.CountSpareKeys(ctx, common.CurveSecp256k1ECDSABitcoin, common.RequestFlagNone, common.RequestRoleObserver)
	if err != nil {
		return err
	}
	for count < 1000 {
		observer, chainCode, err := node.store.ReadObserverKey(ctx, common.CurveSecp256k1ECDSABitcoin)
		if err != nil {
			return err
		}
		if observer == "" {
			return nil
		}
		id := mixin.UniqueConversationID(observer, observer)
		extra := append([]byte{common.RequestRoleObserver}, chainCode...)
		extra = append(extra, common.RequestFlagNone)
		err = node.sendKeeperResponse(ctx, observer, common.ActionObserverAddKey, keeper.SafeChainBitcoin, id, extra)
		if err != nil {
			return err
		}
		err = node.store.DeleteObserverKey(ctx, observer)
		if err != nil {
			return err
		}
		count++
	}
	return nil
}

func (node *Node) bitcoinRequestSignerKeys(ctx context.Context) error {
	count, err := node.keeperStore.CountSpareKeys(ctx, common.CurveSecp256k1ECDSABitcoin, common.RequestFlagNone, common.RequestRoleSigner)
	if err != nil || count > 1000 {
		return err
	}
	requested, err := node.readSignerKeygenRequestTime(ctx)
	if err != nil || requested.Add(60*time.Minute).After(time.Now()) {
		return err
	}
	dummy := node.bitcoinDummyHolder()
	id := mixin.UniqueConversationID(requested.String(), requested.String())
	err = node.sendKeeperResponse(ctx, dummy, common.ActionObserverRequestSignerKeys, keeper.SafeChainBitcoin, id, []byte{64})
	if err != nil {
		return err
	}
	return node.writeSignerKeygenRequestTime(ctx)
}

func (node *Node) readSignerKeygenRequestTime(ctx context.Context) (time.Time, error) {
	val, err := node.store.ReadProperty(ctx, bitcoinKeygenRequestTimeKey)
	if err != nil || val == "" {
		return time.Unix(0, node.conf.Timestamp), err
	}
	return time.Parse(time.RFC3339Nano, val)
}

func (node *Node) writeSignerKeygenRequestTime(ctx context.Context) error {
	return node.store.WriteProperty(ctx, bitcoinKeygenRequestTimeKey, time.Now().Format(time.RFC3339Nano))
}
