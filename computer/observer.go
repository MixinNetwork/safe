package computer

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

func (node *Node) bootObserver(ctx context.Context) {
	if string(node.id) != node.conf.ObserverId {
		return
	}
	logger.Printf("bootObserver(%s)", node.id)
	go node.StartHTTP()

	err := node.initMpcKeys(ctx)
	if err != nil {
		panic(err)
	}
	err = node.sendPriceInfo(ctx)
	if err != nil {
		panic(err)
	}

	go node.createNonceAccountLoop(ctx)
	go node.releaseNonceAccountLoop(ctx)

	go node.withdrawalFeeLoop(ctx)
	go node.withdrawalConfirmLoop(ctx)

	go node.unconfirmedCallLoop(ctx)
	go node.initialCallLoop(ctx)
	go node.unsignedCallLoop(ctx)
	go node.signedCallLoop(ctx)

	go node.solanaRPCBlocksLoop(ctx)
}

func (node *Node) initMpcKeys(ctx context.Context) error {
	for {
		count, err := node.store.CountKeys(ctx)
		if err != nil || count >= node.conf.MpcKeyNumber {
			return err
		}

		now := time.Now().UTC()
		requestAt := node.readPropertyAsTime(ctx, store.KeygenRequestTimeKey)
		if now.Before(requestAt.Add(frostKeygenRoundTimeout + 1*time.Minute)) {
			time.Sleep(1 * time.Minute)
			continue
		}

		for i := count; i < node.conf.MpcKeyNumber; i++ {
			id := common.UniqueId("mpc base key", fmt.Sprintf("%d", i))
			id = common.UniqueId(id, now.String())
			extra := []byte{byte(i)}
			err = node.sendObserverTransactionToGroup(ctx, &common.Operation{
				Id:    id,
				Type:  OperationTypeKeygenInput,
				Extra: extra,
			})
			if err != nil {
				return err
			}
		}

		err = node.writeRequestTime(ctx, store.KeygenRequestTimeKey, now)
		if err != nil {
			return err
		}
	}
}

func (node *Node) sendPriceInfo(ctx context.Context) error {
	amount := decimal.RequireFromString(node.conf.OperationPriceAmount)
	logger.Printf("node.sendPriceInfo(%s, %s)", node.conf.OperationPriceAssetId, amount)
	amount = amount.Mul(decimal.New(1, 8))
	if amount.Sign() <= 0 || !amount.IsInteger() || !amount.BigInt().IsInt64() {
		panic(node.conf.OperationPriceAmount)
	}
	id := common.UniqueId("OperationTypeSetOperationParams", node.conf.OperationPriceAssetId)
	id = common.UniqueId(id, amount.String())
	extra := uuid.Must(uuid.FromString(node.conf.OperationPriceAssetId)).Bytes()
	extra = binary.BigEndian.AppendUint64(extra, uint64(amount.IntPart()))
	return node.sendObserverTransactionToGroup(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeSetOperationParams,
		Extra: extra,
	})
}

func (node *Node) createNonceAccountLoop(ctx context.Context) {
	for {
		err := node.createNonceAccounts(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(1 * time.Minute)
	}
}

func (node *Node) releaseNonceAccountLoop(ctx context.Context) {
	for {
		err := node.releaseNonceAccounts(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(1 * time.Minute)
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

		time.Sleep(1 * time.Minute)
	}
}

func (node *Node) unconfirmedCallLoop(ctx context.Context) {
	for {
		err := node.handleUnconfirmedCalls(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(1 * time.Minute)
	}
}

func (node *Node) initialCallLoop(ctx context.Context) {
	for {
		err := node.handleInitialCalls(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(1 * time.Minute)
	}
}

func (node *Node) unsignedCallLoop(ctx context.Context) {
	for {
		err := node.processUnsignedCalls(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(1 * time.Minute)
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

func (node *Node) createNonceAccounts(ctx context.Context) error {
	count, err := node.store.CountNonceAccounts(ctx)
	if err != nil || count > 100 {
		return err
	}
	requested := node.readPropertyAsTime(ctx, store.NonceAccountRequestTimeKey)
	if requested.Add(1 * time.Minute).After(time.Now().UTC()) {
		return nil
	}
	address, hash, err := node.CreateNonceAccount(ctx)
	if err != nil {
		return fmt.Errorf("node.CreateNonceAccount() => %v", err)
	}
	err = node.store.WriteNonceAccount(ctx, address, hash)
	if err != nil {
		return fmt.Errorf("store.WriteNonceAccount(%s %s) => %v", address, hash, err)
	}
	return node.writeRequestTime(ctx, store.NonceAccountRequestTimeKey, time.Now().UTC())
}

func (node *Node) releaseNonceAccounts(ctx context.Context) error {
	as, err := node.store.ListLockedNonceAccounts(ctx)
	if err != nil {
		return err
	}
	for _, nonce := range as {
		if nonce.UpdatedAt.Add(20 * time.Minute).After(time.Now()) {
			continue
		}
		err = node.store.ReleaseLockedNonceAccount(ctx, nonce.Address)
		if err != nil {
			return err
		}
	}
	return nil
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
	start := node.readPropertyAsTime(ctx, store.WithdrawalConfirmRequestTimeKey)
	txs := node.group.ListConfirmedWithdrawalTransactionsAfter(ctx, start, 100)
	for _, tx := range txs {
		id := common.UniqueId(tx.TraceId, "confirm-withdrawal")
		sig := solana.MustSignatureFromBase58(tx.WithdrawalHash.String)
		extra := uuid.Must(uuid.FromString(tx.TraceId)).Bytes()
		extra = append(extra, uuid.Must(uuid.FromString(tx.Memo)).Bytes()...)
		extra = append(extra, sig[:]...)
		err := node.sendObserverTransactionToGroup(ctx, &common.Operation{
			Id:    id,
			Type:  OperationTypeConfirmWithdrawal,
			Extra: extra,
		})
		if err != nil {
			return err
		}
		err = node.writeRequestTime(ctx, store.WithdrawalConfirmRequestTimeKey, tx.UpdatedAt)
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) handleUnconfirmedCalls(ctx context.Context) error {
	calls, err := node.store.ListUnconfirmedSystemCalls(ctx)
	if err != nil {
		return err
	}
	for _, call := range calls {
		nonce, err := node.store.ReadNonceAccount(ctx, call.NonceAccount)
		if err != nil {
			return err
		}
		id := common.UniqueId(call.RequestId, "confirm")
		extra := []byte{ConfirmFlagNonceAvailable}
		if nonce == nil || nonce.CallId.Valid || !nonce.Mix.Valid {
			id = common.UniqueId(id, "expired")
			extra = []byte{ConfirmFlagNonceExpired}
		}
		extra = append(extra, uuid.Must(uuid.FromString(call.RequestId)).Bytes()...)
		err = node.sendObserverTransactionToGroup(ctx, &common.Operation{
			Id:    id,
			Type:  ConfirmFlagNonceAvailable,
			Extra: extra,
		})
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
		tx, as := node.transferOrMintTokens(ctx, call, nonce)
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
		err = node.sendObserverTransactionToGroup(ctx, &common.Operation{
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

func (node *Node) processUnsignedCalls(ctx context.Context) error {
	calls, err := node.store.ListUnsignedCalls(ctx)
	if err != nil {
		return err
	}
	for _, call := range calls {
		createdAt := time.Now().UTC()
		if call.RequestSignerAt.Time.Add(20 * time.Minute).After(createdAt) {
			continue
		}
		if call.RequestSignerAt.Valid {
			createdAt = call.RequestSignerAt.Time
		}
		id := common.UniqueId(call.RequestId, createdAt.String())
		extra := uuid.Must(uuid.FromString(call.RequestId)).Bytes()
		err = node.sendObserverTransactionToGroup(ctx, &common.Operation{
			Id:    id,
			Type:  OperationTypeSignInput,
			Extra: extra,
		})
		if err != nil {
			return err
		}
		time.Sleep(5 * time.Second)
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
		hash, err := node.solanaClient().SendTransaction(ctx, tx)
		if err != nil {
			panic(err)
		}
		rpcTx, err := node.solanaClient().RPCGetTransaction(ctx, hash)
		if err != nil {
			panic(err)
		}
		ttx, err := rpcTx.Transaction.GetTransaction()
		if err != nil {
			panic(err)
		}
		err = node.solanaProcessTransaction(ctx, ttx, rpcTx.Meta)
		if err != nil {
			return err
		}
		time.Sleep(1 * time.Minute)
	}
	return nil
}

func (node *Node) readPropertyAsTime(ctx context.Context, key string) time.Time {
	val, err := node.store.ReadProperty(ctx, key)
	if err != nil {
		panic(err)
	}
	if val == "" {
		return time.Unix(0, node.conf.Timestamp)
	}
	ts, err := time.Parse(time.RFC3339Nano, val)
	if err != nil {
		panic(val)
	}
	return ts
}

func (node *Node) writeRequestTime(ctx context.Context, key string, offset time.Time) error {
	return node.store.WriteProperty(ctx, key, offset.Format(time.RFC3339Nano))
}
