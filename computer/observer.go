package computer

import (
	"context"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

func (node *Node) bootObserver(ctx context.Context) {
	go node.keyLoop(ctx)
	go node.initMpcKeyLoop(ctx)
	go node.nonceAccountLoop(ctx)
	go node.withdrawalFeeLoop(ctx)
	go node.withdrawalConfirmLoop(ctx)
	go node.initialCallLoop(ctx)
	go node.signedCallLoop(ctx)
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

func (node *Node) withdrawalFeeLoop(ctx context.Context) {
	for {
		err := node.handleWithdrawalsFee(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(10 * time.Minute)
	}
}

func (node *Node) withdrawalConfirmLoop(ctx context.Context) {
	for {
		err := node.handleWithdrawalsConfirm(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(10 * time.Minute)
	}
}

func (node *Node) initialCallLoop(ctx context.Context) {
	for {
		err := node.handleInitialCalls(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(10 * time.Minute)
	}
}

func (node *Node) signedCallLoop(ctx context.Context) {
	for {
		err := node.handleSignedCalls(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(1 * time.Minute)
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
	key, err := node.store.ReadFirstGeneratedKey(ctx)
	if err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("fail to find first generated key")
	}

	id := common.UniqueId(key, "mtg key init")
	extra := common.DecodeHexOrPanic(key)
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

func (node *Node) handleWithdrawalsFee(ctx context.Context) error {
	txs := node.group.ListUnconfirmedWithdrawalTransactions(ctx, 500)
	for _, tx := range txs {
		if !tx.Destination.Valid {
			panic(tx.TraceId)
		}
		asset, err := common.SafeReadAssetUntilSufficient(ctx, node.mixin, tx.AssetId)
		if err != nil {
			return err
		}
		if asset.ChainID != common.SafeSolanaChainId {
			continue
		}
		fee, err := common.SafeReadWithdrawalFeeUntilSufficient(ctx, node.safeUser(), asset.AssetID, common.SafeSolanaChainId, tx.Destination.String)
		if err != nil {
			return err
		}
		if fee.AssetID != common.SafeSolanaChainId {
			panic(fee.AssetID)
		}
		rid := common.UniqueId(tx.TraceId, "withdrawal_fee")
		amount, _ := decimal.NewFromString(fee.Amount)
		refs := common.ToMixinnetHash([]crypto.Hash{tx.Hash})
		_, err = common.SendTransactionUntilSufficient(ctx, node.mixin, []string{node.conf.MTG.App.AppId}, 1, []string{mtg.MixinFeeUserId}, 1, amount, rid, fee.AssetID, "", refs, node.conf.MTG.App.SpendPrivateKey)
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) handleWithdrawalsConfirm(ctx context.Context) error {
	start, err := node.readRequestSequence(ctx, store.WithdrawalConfirmRequestSequence)
	if err != nil {
		return err
	}
	txs := node.group.ListConfirmedWithdrawalTransactionsBySequence(ctx, start, 100)
	for _, tx := range txs {
		id := common.UniqueId(tx.TraceId, "confirm-withdrawal")
		extra := uuid.Must(uuid.FromString(tx.TraceId)).Bytes()
		extra = append(extra, uuid.Must(uuid.FromString(tx.Memo)).Bytes()...)
		extra = append(extra, []byte(tx.WithdrawalHash.String)...)
		err = node.sendObserverTransaction(ctx, &common.Operation{
			Id:    id,
			Type:  OperationTypeConfirmWithdrawal,
			Extra: extra,
		})
		if err != nil {
			return err
		}
		err = node.writeRequestSequence(ctx, store.WithdrawalConfirmRequestSequence, tx.Sequence)
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) handleInitialCalls(ctx context.Context) error {
	calls, err := node.store.ListInitialSystemCalls(ctx)
	if err != nil {
		return err
	}
	for _, call := range calls {
		nonce, err := node.store.ReadSpareNonceAccount(ctx)
		if err != nil {
			return err
		}
		tx, as := node.mintExternalTokens(ctx, call, nonce)
		data, err := tx.MarshalBinary()
		if err != nil {
			panic(err)
		}
		id := common.UniqueId(call.RequestId, "mints-tx-storage")
		hash, err := common.WriteStorageUntilSufficient(ctx, node.mixin, data, id, *node.safeUser())
		if err != nil {
			return err
		}
		id = common.UniqueId(id, "mints-tx")
		extra := uuid.Must(uuid.FromString(call.RequestId)).Bytes()
		extra = append(extra, solana.MustPublicKeyFromBase58(nonce.Address).Bytes()...)
		extra = append(extra, hash[:]...)
		for _, asset := range as {
			if asset.PrivateKey == nil {
				continue
			}
			extra = append(extra, uuid.Must(uuid.FromString(asset.AssetId)).Bytes()...)
			extra = append(extra, solana.MustPublicKeyFromBase58(asset.Address).Bytes()...)
		}
		err = node.sendObserverTransaction(ctx, &common.Operation{
			Id:    id,
			Type:  OperationTypeCreateSubCall,
			Extra: extra,
		})
		if err != nil {
			return err
		}
		time.Sleep(1 * time.Minute)
	}
	return nil
}

func (node *Node) handleSignedCalls(ctx context.Context) error {
	calls, err := node.store.ListSignedCalls(ctx)
	if err != nil {
		return err
	}
	for _, call := range calls {
		publicKey := solanaApp.PublicKeyFromEd25519Public(call.Public)
		tx, err := solana.TransactionFromBase64(call.Raw)
		if err != nil {
			return err
		}
		accounts, err := tx.AccountMetaList()
		if err != nil {
			return err
		}
		index := -1
		for i, account := range accounts {
			if !account.PublicKey.Equals(publicKey) {
				continue
			}
			index = i
		}
		if index == -1 {
			return fmt.Errorf("invalid solana tx signature: %s", call.RequestId)
		}
		tx.Signatures[index] = solana.SignatureFromBytes(common.DecodeHexOrPanic(call.Signature.String))
		err = node.solanaClient().SendAndConfirmTransaction(ctx, tx)
		if err != nil {
			return err
		}
		time.Sleep(1 * time.Minute)
	}
	return nil
}
