package observer

import (
	"context"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/common"
)

func (node *Node) safeKeyLoop(ctx context.Context, chain byte) {
	for {
		err := node.safeRequestSignerKeys(ctx, chain)
		if err != nil {
			panic(err)
		}

		err = node.safeAddObserverKeys(ctx, chain)
		if err != nil {
			panic(err)
		}

		time.Sleep(10 * time.Minute)
	}
}

func (node *Node) safeAddObserverKeys(ctx context.Context, chain byte) error {
	var crv byte
	switch chain {
	case common.SafeChainBitcoin:
		crv = common.CurveSecp256k1ECDSABitcoin
	case common.SafeChainEthereum:
		crv = common.CurveSecp256k1ECDSAEthereum
	}
	count, err := node.keeperStore.CountSpareKeys(ctx, crv, common.RequestFlagNone, common.RequestRoleObserver)
	if err != nil {
		return err
	}
	for count < 1000 {
		observer, chainCode, err := node.store.ReadObserverKey(ctx, crv)
		if err != nil {
			return err
		}
		if observer == "" {
			return nil
		}
		err = node.store.DeleteObserverKey(ctx, observer)
		if err != nil {
			return err
		}

		old, err := node.keeperStore.ReadKey(ctx, observer)
		if err != nil {
			return err
		}
		if old != nil {
			continue
		}

		id := common.UniqueId(observer, observer)
		extra := append([]byte{common.RequestRoleObserver}, chainCode...)
		extra = append(extra, common.RequestFlagNone)
		err = node.sendKeeperResponse(ctx, observer, common.ActionObserverAddKey, chain, id, extra)
		if err != nil {
			return err
		}
		count++
	}
	return nil
}

func (node *Node) safeRequestSignerKeys(ctx context.Context, chain byte) error {
	var crv byte
	switch chain {
	case common.SafeChainBitcoin:
		crv = common.CurveSecp256k1ECDSABitcoin
	case common.SafeChainEthereum:
		crv = common.CurveSecp256k1ECDSAEthereum
	}
	count, err := node.keeperStore.CountSpareKeys(ctx, crv, common.RequestFlagNone, common.RequestRoleSigner)
	if err != nil || count > 1000 {
		return err
	}
	requested, err := node.readSignerKeygenRequestTime(ctx, chain)
	if err != nil || requested.Add(60*time.Minute).After(time.Now()) {
		return err
	}
	dummy := node.bitcoinDummyHolder()
	id := common.UniqueId(requested.String(), requested.String())
	keysCount := []byte{16}
	err = node.sendKeeperResponse(ctx, dummy, common.ActionObserverRequestSignerKeys, chain, id, keysCount)
	if err != nil {
		return err
	}
	return node.writeSignerKeygenRequestTime(ctx, chain)
}

func (node *Node) readSignerKeygenRequestTime(ctx context.Context, chain byte) (time.Time, error) {
	key, err := node.chainKeygenRequestTimeKey(chain)
	if err != nil {
		return time.Unix(0, node.conf.Timestamp), err
	}
	val, err := node.store.ReadProperty(ctx, key)
	if err != nil || val == "" {
		return time.Unix(0, node.conf.Timestamp), err
	}
	return time.Parse(time.RFC3339Nano, val)
}

func (node *Node) writeSignerKeygenRequestTime(ctx context.Context, chain byte) error {
	key, err := node.chainKeygenRequestTimeKey(chain)
	if err != nil {
		return err
	}
	return node.store.WriteProperty(ctx, key, time.Now().Format(time.RFC3339Nano))
}

func (node *Node) chainKeygenRequestTimeKey(chain byte) (string, error) {
	switch chain {
	case common.SafeChainBitcoin:
		return bitcoinKeygenRequestTimeKey, nil
	case common.SafeChainEthereum:
		return ethereumKeygenRequestTimeKey, nil
	default:
		return "", fmt.Errorf("invalid keygen request chain")
	}
}
