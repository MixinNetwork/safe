package observer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/btcsuite/btcd/btcec/v2"
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

		err = node.bitcoinAddAccountantKeys(ctx)
		if err != nil {
			panic(err)
		}
		time.Sleep(10 * time.Minute)
	}
}

func (node *Node) bitcoinAddAccountantKeys(ctx context.Context) error {
	count, err := node.keeperStore.CountSpareKeys(ctx, common.CurveSecp256k1ECDSABitcoin, common.RequestRoleAccountant)
	if err != nil {
		return err
	}
	for count < 1000 {
		accountant, err := node.generateAndWriteBitcoinAccountantKey(ctx)
		if err != nil {
			return err
		}
		id := mixin.UniqueConversationID(accountant, accountant)
		err = node.sendBitcoinKeeperResponse(ctx, accountant, common.ActionObserverAddKey, keeper.SafeChainBitcoin, id, []byte{common.RequestRoleAccountant})
		if err != nil {
			return err
		}
		count++
	}
	return nil
}

func (node *Node) bitcoinAddObserverKeys(ctx context.Context) error {
	count, err := node.keeperStore.CountSpareKeys(ctx, common.CurveSecp256k1ECDSABitcoin, common.RequestRoleObserver)
	if err != nil {
		return err
	}
	for count < 1000 {
		observer, err := node.store.ReadObserverKey(ctx, keeper.SafeChainBitcoin)
		if err != nil {
			return err
		}
		if observer == "" {
			return nil
		}
		id := mixin.UniqueConversationID(observer, observer)
		err = node.sendBitcoinKeeperResponse(ctx, observer, common.ActionObserverAddKey, keeper.SafeChainBitcoin, id, []byte{common.RequestRoleObserver})
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
	count, err := node.keeperStore.CountSpareKeys(ctx, common.CurveSecp256k1ECDSABitcoin, common.RequestRoleSigner)
	if err != nil || count > 1000 {
		return err
	}
	requested, err := node.readSignerKeygenRequestTime(ctx)
	if err != nil || requested.Add(60*time.Minute).After(time.Now()) {
		return err
	}
	dummy := node.bitcoinDummyHolder()
	id := mixin.UniqueConversationID(requested.String(), requested.String())
	err = node.sendBitcoinKeeperResponse(ctx, dummy, common.ActionObserverRequestSignerKeys, keeper.SafeChainBitcoin, id, []byte{64})
	if err != nil {
		return err
	}
	return node.writeSignerKeygenRequestTime(ctx)
}

func (node *Node) generateAndWriteBitcoinAccountantKey(ctx context.Context) (string, error) {
	seed := make([]byte, 32)
	n, err := rand.Read(seed)
	if err != nil || n != 32 {
		panic(err)
	}
	privateKey, publicKey := btcec.PrivKeyFromBytes(seed)
	priv := hex.EncodeToString(privateKey.Serialize())
	pub := hex.EncodeToString(publicKey.SerializeCompressed())
	err = node.store.WriteAccountantKey(ctx, keeper.SafeChainBitcoin, pub, priv)
	return pub, err
}

func (node *Node) bitcoinReadAccountantKey(ctx context.Context, pub string) (*btcec.PrivateKey, error) {
	priv, err := node.store.ReadAccountantKey(ctx, pub, keeper.SafeChainBitcoin)
	if err != nil {
		return nil, err
	}
	b := common.DecodeHexOrPanic(priv)
	privateKey, publicKey := btcec.PrivKeyFromBytes(b)
	if pub != hex.EncodeToString(publicKey.SerializeCompressed()) {
		panic(pub)
	}
	return privateKey, nil
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
