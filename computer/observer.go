package computer

import (
	"context"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
)

func (node *Node) bootObserver(ctx context.Context) {
	go node.keyLoop(ctx)
	go node.initMpcKeyLoop(ctx)
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

		count, err := node.store.CountSpareKeys(ctx)
		if err != nil {
			panic(err)
		}
		if count != 0 {
			err = node.requestInitMpcKey(ctx)
			if err != nil {
				panic(err)
			}
		}
		time.Sleep(10 * time.Minute)
	}
}

func (node *Node) requestKeys(ctx context.Context) error {
	count, err := node.store.CountSpareKeys(ctx)
	if err != nil || count > 1000 {
		return err
	}
	requested, err := node.readSignerKeygenRequestTime(ctx)
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
	return node.writeSignerKeygenRequestTime(ctx)
}

func (node *Node) requestInitMpcKey(ctx context.Context) error {
	key, err := node.store.ReadFirstGeneratedKey(ctx, OperationTypeKeygenInput)
	if err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("fail to find first generated key")
	}
	id := common.UniqueId(key, "mpc key init")
	extra := common.DecodeHexOrPanic(key)
	return node.sendObserverTransaction(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeInitMPCKey,
		Extra: extra,
	})
}

func (node *Node) readSignerKeygenRequestTime(ctx context.Context) (time.Time, error) {
	val, err := node.store.ReadProperty(ctx, store.KeygenRequestTimeKey)
	if err != nil || val == "" {
		return time.Unix(0, node.conf.Timestamp), err
	}
	return time.Parse(time.RFC3339Nano, val)
}

func (node *Node) writeSignerKeygenRequestTime(ctx context.Context) error {
	return node.store.WriteProperty(ctx, store.KeygenRequestTimeKey, time.Now().Format(time.RFC3339Nano))
}
