package computer

import (
	"context"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	solana "github.com/gagliardetto/solana-go"
)

func (node *Node) bootObserver(ctx context.Context) {
	go node.keyLoop(ctx)
	go node.initMpcKeyLoop(ctx)
	go node.nonceAccountLoop(ctx)
}

func (node *Node) keyLoop(ctx context.Context) {
	for {
		err := node.requestKeys(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(10 * time.Minute)
	}
}

func (node *Node) initMpcKeyLoop(ctx context.Context) {
	for {
		initialized, err := node.store.CheckMpcKeyInitialized(ctx)
		if err != nil {
			panic(err)
		}
		if initialized {
			break
		}

		countKey, err := node.store.CountSpareKeys(ctx)
		if err != nil {
			panic(err)
		}
		countNonce, err := node.store.CountSpareNonceAccounts(ctx)
		if err != nil {
			panic(err)
		}
		if countKey > 0 && countNonce > 0 {
			err = node.requestInitMpcKey(ctx)
			if err != nil {
				panic(err)
			}
		}
		time.Sleep(10 * time.Minute)
	}
}

func (node *Node) nonceAccountLoop(ctx context.Context) {
	for {
		err := node.requestNonceAccounts(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(10 * time.Minute)
	}
}

func (node *Node) requestKeys(ctx context.Context) error {
	count, err := node.store.CountSpareKeys(ctx)
	if err != nil || count > 1000 {
		return err
	}
	requested, err := node.readRequestTime(ctx, store.KeygenRequestTimeKey)
	if err != nil || requested.Add(60*time.Minute).After(time.Now()) {
		return err
	}
	id := common.UniqueId(requested.String(), requested.String())
	keysCount := []byte{16}
	err = node.sendObserverTransaction(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeKeygenInput,
		Extra: keysCount,
	})
	if err != nil {
		return err
	}
	return node.writeRequestTime(ctx, store.KeygenRequestTimeKey)
}

func (node *Node) requestInitMpcKey(ctx context.Context) error {
	key, err := node.store.ReadFirstGeneratedKey(ctx, OperationTypeKeygenInput)
	if err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("fail to find first generated key")
	}
	account, err := node.store.ReadSpareNonceAccount(ctx)
	if err != nil {
		return err
	}
	if account == nil {
		return fmt.Errorf("fail to find first generated nonce account")
	}
	addr := solana.MustPublicKeyFromBase58(account.Address)

	id := common.UniqueId(key, account.Address)
	extra := common.DecodeHexOrPanic(key)
	extra = append(extra, addr.Bytes()...)
	return node.sendObserverTransaction(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeInitMPCKey,
		Extra: extra,
	})
}

func (node *Node) requestNonceAccounts(ctx context.Context) error {
	count, err := node.store.CountSpareNonceAccounts(ctx)
	if err != nil || count > 1000 {
		return err
	}
	requested, err := node.readRequestTime(ctx, store.NonceAccountRequestTimeKey)
	if err != nil || requested.Add(60*time.Minute).After(time.Now()) {
		return err
	}
	id := common.UniqueId(requested.String(), requested.String())

	nonceAccountPublic, nonceAccountHash, err := node.CreateNonceAccount(ctx)
	if err != nil {
		return fmt.Errorf("node.CreateNonceAccount() => %v", err)
	}
	extra := nonceAccountPublic.Bytes()
	extra = append(extra, nonceAccountHash[:]...)
	err = node.sendObserverTransaction(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeCreateNonce,
		Extra: extra,
	})
	if err != nil {
		return err
	}
	return node.writeRequestTime(ctx, store.NonceAccountRequestTimeKey)
}

func (node *Node) readRequestTime(ctx context.Context, key string) (time.Time, error) {
	val, err := node.store.ReadProperty(ctx, key)
	if err != nil || val == "" {
		return time.Unix(0, node.conf.Timestamp), err
	}
	return time.Parse(time.RFC3339Nano, val)
}

func (node *Node) writeRequestTime(ctx context.Context, key string) error {
	return node.store.WriteProperty(ctx, key, time.Now().Format(time.RFC3339Nano))
}
