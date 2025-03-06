package computer

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

func (node *Node) bootObserver(ctx context.Context, version string) {
	if string(node.id) != node.conf.ObserverId {
		return
	}
	logger.Printf("bootObserver(%s)", node.id)
	go node.StartHTTP(version)

	err := node.initMPCKeys(ctx)
	if err != nil {
		panic(err)
	}
	err = node.sendPriceInfo(ctx)
	if err != nil {
		panic(err)
	}
	err = node.checkNonceAccounts(ctx)
	if err != nil {
		panic(err)
	}

	go node.deployOrConfirmAssetsLoop(ctx)

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

func (node *Node) initMPCKeys(ctx context.Context) error {
	for {
		count, err := node.store.CountKeys(ctx)
		if err != nil || count >= node.conf.MPCKeyNumber {
			return err
		}

		now := time.Now().UTC()
		requestAt := node.readPropertyAsTime(ctx, store.KeygenRequestTimeKey)
		if now.Before(requestAt.Add(frostKeygenRoundTimeout + 1*time.Minute)) {
			time.Sleep(1 * time.Minute)
			continue
		}

		for i := count; i < node.conf.MPCKeyNumber; i++ {
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

func (node *Node) deployOrConfirmAssetsLoop(ctx context.Context) {
	for {
		err := node.deployOrConfirmAssets(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(1 * time.Minute)
	}
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

func (node *Node) deployOrConfirmAssets(ctx context.Context) error {
	es, err := node.store.ListUnrequestedAssets(ctx)
	if err != nil || len(es) == 0 {
		return err
	}
	var as []string
	for _, a := range es {
		old, err := node.store.ReadDeployedAsset(ctx, a.AssetId, 0)
		if err != nil {
			return err
		}
		if old == nil {
			as = append(as, a.AssetId)
			continue
		}
		err = node.store.MarkExternalAssetRequested(ctx, a.AssetId)
		if err != nil {
			return err
		}
	}
	nonce, err := node.store.ReadSpareNonceAccount(ctx)
	if err != nil || nonce == nil {
		return fmt.Errorf("store.ReadSpareNonceAccount() => %v %v", nonce, err)
	}
	tid, tx, assets, err := node.CreateMintsTransaction(ctx, as, nonce)
	if err != nil || tx == nil {
		return err
	}
	data, err := tx.MarshalBinary()
	if err != nil {
		return err
	}
	hash, err := common.WriteStorageUntilSufficient(ctx, node.mixin, data, common.UniqueId(tid, "storage-tx"), *node.safeUser())
	if err != nil {
		return err
	}

	extra := uuid.Must(uuid.FromString(tid)).Bytes()
	extra = append(extra, hash[:]...)
	for _, asset := range assets {
		extra = append(extra, uuid.Must(uuid.FromString(asset.AssetId)).Bytes()...)
		extra = append(extra, solana.MustPublicKeyFromBase58(asset.Address).Bytes()...)
	}
	return node.sendObserverTransactionToGroup(ctx, &common.Operation{
		Id:    tid,
		Type:  OperationTypeDeployExternalAssets,
		Extra: extra,
	})
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
	address, hash, err := node.CreateNonceAccount(ctx, count)
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
		asset, err := common.SafeReadAssetUntilSufficient(ctx, tx.AssetId)
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
		id := common.UniqueId(call.RequestId, "confirm-nonce")
		extra := []byte{ConfirmFlagNonceAvailable}
		if nonce == nil || nonce.CallId.Valid || !nonce.Mix.Valid {
			id = common.UniqueId(id, "expired-nonce")
			extra = []byte{ConfirmFlagNonceExpired}
		}
		extra = append(extra, uuid.Must(uuid.FromString(call.RequestId)).Bytes()...)
		err = node.sendObserverTransactionToGroup(ctx, &common.Operation{
			Id:    id,
			Type:  OperationTypeConfirmNonce,
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
		tx, err := node.transferOrMintTokens(ctx, call, nonce)
		if err != nil {
			return err
		}
		data, err := tx.MarshalBinary()
		if err != nil {
			panic(err)
		}
		id := common.UniqueId(call.RequestId, store.CallTypePrepare)
		old, err := node.store.ReadSystemCallByRequestId(ctx, id, 0)
		if err != nil {
			panic(err)
		}
		if old != nil && old.State == common.RequestStateFailed {
			id = common.UniqueId(id, old.RequestId)
		}
		hash, err := common.WriteStorageUntilSufficient(ctx, node.mixin, data, common.UniqueId(id, "storage"), *node.safeUser())
		if err != nil {
			return err
		}
		err = node.store.OccupyNonceAccountByCall(ctx, nonce.Address, id)
		if err != nil {
			return err
		}
		extra := uuid.Must(uuid.FromString(id)).Bytes()
		extra = append(extra, uuid.Must(uuid.FromString(call.RequestId)).Bytes()...)
		extra = append(extra, hash[:]...)
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
	payer := solana.MustPrivateKeyFromBase58(node.conf.SolanaKey)
	calls, err := node.store.ListSignedCalls(ctx)
	if err != nil {
		return err
	}
	for _, call := range calls {
		logger.Printf("node.handleSignedCalls(%s)", call.RequestId)
		publicKey := node.getUserSolanaPublicKeyFromCall(ctx, call)
		tx, err := solana.TransactionFromBase64(call.Raw)
		if err != nil {
			return err
		}
		err = node.solanaClient().ProcessTransactionWithAddressLookups(ctx, tx)
		if err != nil {
			return err
		}
		_, err = tx.PartialSign(solanaApp.BuildSignersGetter(payer))
		if err != nil {
			panic(err)
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
		sig, err := base64.StdEncoding.DecodeString(call.Signature.String)
		if err != nil {
			panic(err)
		}
		tx.Signatures[index] = solana.SignatureFromBytes(sig)

		hash, err := node.solanaClient().SendTransaction(ctx, tx)
		if err != nil {
			logger.Printf("solana.SendTransaction(%s) => %v", call.RequestId, err)
			return node.handleFailedCall(ctx, call)
		}
		var meta *rpc.TransactionMeta
		for {
			rpcTx, err := node.solanaClient().RPCGetTransaction(ctx, hash)
			if rpcTx != nil && err == nil {
				tx, err = rpcTx.Transaction.GetTransaction()
				if err != nil {
					panic(err)
				}
				meta = rpcTx.Meta
				break
			}
			if strings.Contains(err.Error(), "not found") {
				time.Sleep(1 * time.Second)
				continue
			}
			return fmt.Errorf("solana.RPCGetTransaction(%s) => %v", hash, err)
		}
		err = node.solanaProcessTransaction(ctx, tx, meta)
		if err != nil {
			return err
		}
		time.Sleep(1 * time.Minute)
	}
	return nil
}

func (node *Node) handleFailedCall(ctx context.Context, call *store.SystemCall) error {
	id := common.UniqueId(call.RequestId, "confirm-fail")
	extra := []byte{FlagConfirmCallFail}
	extra = append(extra, uuid.Must(uuid.FromString(call.RequestId)).Bytes()...)
	err := node.sendObserverTransactionToGroup(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeConfirmCall,
		Extra: extra,
	})
	if err != nil {
		return err
	}
	if call.Type != store.CallTypeMain {
		return nil
	}

	nonce, err := node.store.ReadSpareNonceAccount(ctx)
	if err != nil {
		panic(err)
	}
	tx := node.clearTokens(ctx, call, node.getMTGAddress(ctx), nonce)
	if tx == nil {
		return nil
	}
	data, err := tx.MarshalBinary()
	if err != nil {
		panic(err)
	}
	id = common.UniqueId(call.RequestId, "post-process")
	old, err := node.store.ReadSystemCallByRequestId(ctx, id, 0)
	if err != nil {
		panic(err)
	}
	if old != nil && old.State == common.RequestStateFailed {
		id = common.UniqueId(id, old.RequestId)
	}
	hash, err := common.WriteStorageUntilSufficient(ctx, node.mixin, data, common.UniqueId(id, "storage"), *node.safeUser())
	if err != nil {
		return err
	}
	err = node.store.OccupyNonceAccountByCall(ctx, nonce.Address, id)
	if err != nil {
		return err
	}
	extra = uuid.Must(uuid.FromString(id)).Bytes()
	extra = append(extra, uuid.Must(uuid.FromString(call.RequestId)).Bytes()...)
	extra = append(extra, hash[:]...)
	return node.sendObserverTransactionToGroup(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeCreateSubCall,
		Extra: extra,
	})
}

func (node *Node) storageSolanaTx(ctx context.Context, raw string) (string, error) {
	rb, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	_, err = solana.TransactionFromBytes(rb)
	if err != nil {
		return "", err
	}
	trace := common.UniqueId(raw, "storage-solana-tx")
	hash, err := common.WriteStorageUntilSufficient(ctx, node.mixin, rb, trace, *node.safeUser())
	if err != nil {
		return "", err
	}
	return hash.String(), nil
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

func (node *Node) checkNonceAccounts(ctx context.Context) error {
	nonces, err := node.store.ListNonceAccounts(ctx)
	if err != nil {
		return err
	}
	for _, nonce := range nonces {
		hash, err := node.solanaClient().GetNonceAccountHash(ctx, nonce.Account().Address)
		if err != nil {
			return err
		}
		if hash.String() == nonce.Hash {
			continue
		}
		err = node.store.UpdateNonceAccount(ctx, nonce.Address, hash.String())
		if err != nil {
			return err
		}
	}
	return nil
}
