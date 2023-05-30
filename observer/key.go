package observer

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
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
		accountant, chainCode, err := node.generateAndWriteBitcoinAccountantKey(ctx)
		if err != nil {
			return err
		}
		id := mixin.UniqueConversationID(accountant, accountant)
		extra := append([]byte{common.RequestRoleAccountant}, chainCode...)
		err = node.sendBitcoinKeeperResponse(ctx, accountant, common.ActionObserverAddKey, keeper.SafeChainBitcoin, id, extra)
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
		observer, chainCode, err := node.store.ReadObserverKey(ctx, common.CurveSecp256k1ECDSABitcoin)
		if err != nil {
			return err
		}
		if observer == "" {
			return nil
		}
		id := mixin.UniqueConversationID(observer, observer)
		extra := append([]byte{common.RequestRoleObserver}, chainCode...)
		err = node.sendBitcoinKeeperResponse(ctx, observer, common.ActionObserverAddKey, keeper.SafeChainBitcoin, id, extra)
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

func (node *Node) generateAndWriteBitcoinAccountantKey(ctx context.Context) (string, []byte, error) {
	seed := make([]byte, 64)
	n, err := rand.Read(seed)
	if err != nil || n != 64 {
		panic(err)
	}

	hmac512 := hmac.New(sha512.New, seed)
	_, _ = hmac512.Write(seed)
	lr := hmac512.Sum(nil)

	secretKey := lr[:len(lr)/2]
	chainCode := lr[len(lr)/2:]

	secretKeyNum := new(big.Int).SetBytes(secretKey)
	if secretKeyNum.Cmp(btcec.S256().N) >= 0 || secretKeyNum.Sign() == 0 {
		panic(secretKeyNum.String())
	}

	privateKey, publicKey := btcec.PrivKeyFromBytes(secretKey)
	priv := hex.EncodeToString(privateKey.Serialize())
	pub := hex.EncodeToString(publicKey.SerializeCompressed())
	err = node.store.WriteAccountantKey(ctx, common.CurveSecp256k1ECDSABitcoin, pub, priv, chainCode)
	return pub, chainCode, err
}

func (node *Node) bitcoinReadAccountantKey(ctx context.Context, pub string) (*btcec.PrivateKey, error) {
	priv, err := node.store.ReadAccountantKey(ctx, pub, common.CurveSecp256k1ECDSABitcoin)
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
