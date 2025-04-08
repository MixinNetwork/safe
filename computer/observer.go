package computer

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/safe/mtg"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	loopInterval = time.Second * 5
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

	go node.initializeUsersLoop(ctx)
	go node.deployOrConfirmAssetsLoop(ctx)

	go node.createNonceAccountLoop(ctx)
	go node.releaseNonceAccountLoop(ctx)

	go node.feeInfoLoop(ctx)
	go node.withdrawalFeeLoop(ctx)

	go node.unconfirmedCallLoop(ctx)
	go node.unwithdrawnCallLoop(ctx)
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
			}, nil)
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
	}, nil)
}

func (node *Node) initializeUsersLoop(ctx context.Context) {
	for {
		err := node.initializeUsers(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(loopInterval)
	}
}

func (node *Node) deployOrConfirmAssetsLoop(ctx context.Context) {
	for {
		err := node.deployOrConfirmAssets(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(loopInterval)
	}
}

func (node *Node) createNonceAccountLoop(ctx context.Context) {
	for {
		err := node.createNonceAccounts(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(loopInterval)
	}
}

func (node *Node) releaseNonceAccountLoop(ctx context.Context) {
	for {
		err := node.releaseNonceAccounts(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(loopInterval)
	}
}

func (node *Node) feeInfoLoop(ctx context.Context) {
	for {
		err := node.handleFeeInfo(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(40 * time.Minute)
	}
}

func (node *Node) withdrawalFeeLoop(ctx context.Context) {
	for {
		err := node.handleWithdrawalsFee(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(loopInterval)
	}
}

func (node *Node) unwithdrawnCallLoop(ctx context.Context) {
	for {
		err := node.handleUnwithdrawnCalls(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(loopInterval)
	}
}

func (node *Node) unconfirmedCallLoop(ctx context.Context) {
	for {
		err := node.handleUnconfirmedCalls(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(loopInterval)
	}
}

func (node *Node) unsignedCallLoop(ctx context.Context) {
	for {
		err := node.processUnsignedCalls(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(loopInterval)
	}
}

func (node *Node) signedCallLoop(ctx context.Context) {
	for {
		err := node.handleSignedCalls(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(loopInterval)
	}
}

func (node *Node) initializeUsers(ctx context.Context) error {
	offset := node.readPropertyAsTime(ctx, store.UserInitializeTimeKey)
	us, err := node.store.ListNewUsersAfter(ctx, offset)
	if err != nil || len(us) == 0 {
		return err
	}

	for _, u := range us {
		err := node.InitializeAccount(ctx, u)
		if err != nil {
			return err
		}
		err = node.writeRequestTime(ctx, store.UserInitializeTimeKey, u.CreatedAt)
		if err != nil {
			return err
		}
		time.Sleep(loopInterval)
	}
	return nil
}

func (node *Node) deployOrConfirmAssets(ctx context.Context) error {
	es, err := node.store.ListUndeployedAssets(ctx)
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
		if old.State == common.RequestStateDone {
			err = node.store.MarkExternalAssetDeployed(ctx, a.AssetId)
			if err != nil {
				return err
			}
			continue
		}
		if a.RequestedAt.Valid && time.Now().Before(a.RequestedAt.Time.Add(time.Minute*20)) {
			continue
		}
		as = append(as, a.AssetId)
		err = node.store.MarkExternalAssetRequested(ctx, a.AssetId)
		if err != nil {
			return err
		}
	}
	if len(as) == 0 {
		return nil
	}
	tid, tx, assets, err := node.CreateMintsTransaction(ctx, as)
	if err != nil || tx == nil {
		return err
	}
	data, err := tx.MarshalBinary()
	if err != nil {
		return err
	}
	hash, err := node.storageSubSolanaTx(ctx, tid, data)
	if err != nil {
		return err
	}
	references := []crypto.Hash{hash}

	var extra []byte
	for _, asset := range assets {
		extra = append(extra, uuid.Must(uuid.FromString(asset.AssetId)).Bytes()...)
		extra = append(extra, solana.MustPublicKeyFromBase58(asset.Address).Bytes()...)
	}
	return node.sendObserverTransactionToGroup(ctx, &common.Operation{
		Id:    tid,
		Type:  OperationTypeDeployExternalAssets,
		Extra: extra,
	}, references)
}

func (node *Node) createNonceAccounts(ctx context.Context) error {
	count, err := node.store.CountNonceAccounts(ctx)
	if err != nil || count > 100 {
		return err
	}
	requested := node.readPropertyAsTime(ctx, store.NonceAccountRequestTimeKey)
	if requested.Add(10 * time.Second).After(time.Now().UTC()) {
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
		if nonce.LockedByUserOnly() && nonce.Expired() {
			logger.Printf("observer.ReleaseLockedNonceAccount(%v)", nonce)
			err = node.store.ReleaseLockedNonceAccount(ctx, nonce.Address)
			if err != nil {
				return err
			}
			continue
		}

		call, err := node.store.ReadSystemCallByRequestId(ctx, nonce.CallId.String, 0)
		if err != nil {
			return err
		}
		if call == nil {
			if nonce.Expired() {
				logger.Printf("observer.ReleaseLockedNonceAccount(%v %v)", nonce, call)
				err = node.store.ReleaseLockedNonceAccount(ctx, nonce.Address)
				if err != nil {
					panic(err)
				}
			}
			continue
		}
		switch call.State {
		case common.RequestStateFailed:
			logger.Printf("observer.ReleaseLockedNonceAccount(%v %v)", nonce, call)
			err = node.store.ReleaseLockedNonceAccount(ctx, nonce.Address)
			if err != nil {
				panic(err)
			}
		case common.RequestStateDone:
			if nonce.UpdatedBy.Valid && nonce.UpdatedBy.String == call.RequestId {
				err = node.store.ReleaseLockedNonceAccount(ctx, nonce.Address)
				if err != nil {
					panic(err)
				}
			}
			for {
				newNonceHash, err := node.SolanaClient().GetNonceAccountHash(ctx, nonce.Account().Address)
				if err != nil {
					panic(err)
				}
				if newNonceHash.String() == nonce.Hash {
					time.Sleep(3 * time.Second)
					continue
				}
				err = node.store.UpdateNonceAccount(ctx, nonce.Address, newNonceHash.String(), call.RequestId)
				if err != nil {
					panic(err)
				}
				break
			}
		}
	}
	return nil
}

func (node *Node) handleFeeInfo(ctx context.Context) error {
	xin, err := common.SafeReadAssetUntilSufficient(ctx, common.XinKernelAssetId)
	if err != nil {
		return err
	}
	sol, err := common.SafeReadAssetUntilSufficient(ctx, common.SafeSolanaChainId)
	if err != nil {
		return err
	}
	xinPrice, err := decimal.NewFromString(xin.PriceUSD)
	if err != nil {
		return err
	}
	solPrice, err := decimal.NewFromString(sol.PriceUSD)
	if err != nil {
		return err
	}
	ratio := xinPrice.Div(solPrice)

	extra := []byte(ratio.String())
	return node.sendObserverTransactionToGroup(ctx, &common.Operation{
		Id:    common.UniqueId(time.Now().String(), fmt.Sprintf("%s:fee", node.id)),
		Type:  OperationTypeUpdateFeeInfo,
		Extra: extra,
	}, nil)
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
		fee, err := common.SafeReadWithdrawalFeeUntilSufficient(ctx, node.SafeUser(), asset.AssetID, common.SafeSolanaChainId, tx.Destination.String)
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

func (node *Node) handleUnwithdrawnCalls(ctx context.Context) error {
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
		}, nil)
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
		logger.Printf("observer.handleUnconfirmedCall(%s)", call.RequestId)
		nonce, err := node.store.ReadNonceAccount(ctx, call.NonceAccount)
		if err != nil {
			return err
		}

		var references []crypto.Hash
		id := common.UniqueId(call.RequestId, "confirm-nonce")
		extra := []byte{ConfirmFlagNonceAvailable}
		extra = append(extra, uuid.Must(uuid.FromString(call.RequestId)).Bytes()...)

		fee, err := node.getSystemCallFeeFromXin(ctx, call)
		if nonce == nil || !nonce.LockedByUserOnly() || err != nil {
			logger.Printf("observer.expireSystemCall(%v %v %v)", call, nonce, err)
			id = common.UniqueId(id, "expire-nonce")
			extra[0] = ConfirmFlagNonceExpired
		} else {
			cid := common.UniqueId(id, "storage")
			nonce, err := node.store.ReadSpareNonceAccount(ctx)
			if err != nil {
				return err
			}
			err = node.store.OccupyNonceAccountByCall(ctx, nonce.Address, cid)
			if err != nil {
				return err
			}
			tx, err := node.transferOrMintTokens(ctx, call, nonce, fee)
			if err != nil {
				return err
			}
			if tx != nil {
				tb, err := tx.MarshalBinary()
				if err != nil {
					panic(err)
				}
				hash, err := node.storageSubSolanaTx(ctx, cid, tb)
				if err != nil {
					return err
				}
				references = append(references, hash)
			}
		}

		err = node.sendObserverTransactionToGroup(ctx, &common.Operation{
			Id:    id,
			Type:  OperationTypeConfirmNonce,
			Extra: extra,
		}, references)
		logger.Printf("observer.confirmNonce(%s %d %d)", call.RequestId, OperationTypeConfirmNonce, extra[0])
		if err != nil {
			return err
		}
		err = node.store.OccupyNonceAccountByCall(ctx, call.NonceAccount, call.RequestId)
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) processUnsignedCalls(ctx context.Context) error {
	calls, err := node.store.ListUnsignedCalls(ctx)
	if err != nil {
		return err
	}
	for _, call := range calls {
		now := time.Now().UTC()
		if call.RequestSignerAt.Valid && call.RequestSignerAt.Time.Add(20*time.Minute).After(now) {
			continue
		}
		logger.Printf("observer.processUnsignedCalls(%s %d)", call.RequestId, len(calls))
		offset := call.CreatedAt
		if call.RequestSignerAt.Valid {
			offset = call.RequestSignerAt.Time
		}
		id := common.UniqueId(call.RequestId, offset.String())
		extra := uuid.Must(uuid.FromString(call.RequestId)).Bytes()
		err = node.sendObserverTransactionToGroup(ctx, &common.Operation{
			Id:    id,
			Type:  OperationTypeSignInput,
			Extra: extra,
		}, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) handleSignedCalls(ctx context.Context) error {
	balance, err := node.SolanaClient().RPCGetBalance(ctx, node.SolanaPayer())
	if err != nil {
		return err
	}
	if balance < 50000000 {
		logger.Printf("insufficient balance to send tx: %d", balance)
		time.Sleep(30 * time.Second)
		return nil
	}
	calls, err := node.store.ListSignedCalls(ctx)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, call := range calls {
		wg.Add(1)
		go node.handleSignedCall(ctx, &wg, call)
	}
	wg.Wait()
	return nil
}

func (node *Node) handleSignedCall(ctx context.Context, wg *sync.WaitGroup, call *store.SystemCall) error {
	logger.Printf("node.handleSignedCall(%s)", call.RequestId)
	defer wg.Done()

	if call.Type == store.CallTypeMain {
		pending, err := node.store.CheckUnfinishedSubCalls(ctx, call)
		if err != nil {
			panic(err)
		}
		if pending {
			return nil
		}
	}

	payer := solana.MustPrivateKeyFromBase58(node.conf.SolanaKey)
	publicKey := node.getUserSolanaPublicKeyFromCall(ctx, call)
	tx, err := solana.TransactionFromBase64(call.Raw)
	if err != nil {
		return err
	}
	err = node.SolanaClient().ProcessTransactionWithAddressLookups(ctx, tx)
	if err != nil {
		return err
	}
	_, err = tx.PartialSign(solanaApp.BuildSignersGetter(payer))
	if err != nil {
		panic(err)
	}

	index, err := solanaApp.GetSignatureIndexOfAccount(*tx, publicKey)
	if err != nil {
		panic(err)
	}
	if index >= 0 {
		sig, err := base64.StdEncoding.DecodeString(call.Signature.String)
		if err != nil {
			panic(err)
		}
		tx.Signatures[index] = solana.SignatureFromBytes(sig)
	}

	rpcTx, err := node.SendTransactionUtilConfirm(ctx, tx, call)
	logger.Printf("observer.SendTransactionUtilConfirm(%s) => %v", tx.Signatures[0].String(), err)
	if err != nil {
		return node.processFailedCall(ctx, call)
	}
	txx, err := rpcTx.Transaction.GetTransaction()
	if err != nil {
		return err
	}
	return node.processSuccessedCall(ctx, call, txx, rpcTx.Meta)
}

// deposited assets to run system call and new assets received in system call are all handled here
func (node *Node) processSuccessedCall(ctx context.Context, call *store.SystemCall, txx *solana.Transaction, meta *rpc.TransactionMeta) error {
	var references []crypto.Hash
	id := common.UniqueId(call.RequestId, "confirm-success")
	if call.Type == store.CallTypeMain && !call.SkipPostprocess {
		cid := common.UniqueId(id, "post-process")
		nonce, err := node.store.ReadSpareNonceAccount(ctx)
		if err != nil {
			return err
		}
		tx := node.CreatePostprocessTransaction(ctx, call, nonce, txx, meta)
		if tx != nil {
			err = node.store.OccupyNonceAccountByCall(ctx, nonce.Address, cid)
			if err != nil {
				return err
			}
			data, err := tx.MarshalBinary()
			if err != nil {
				panic(err)
			}
			hash, err := node.storageSubSolanaTx(ctx, cid, data)
			if err != nil {
				return err
			}
			references = append(references, hash)
		}
	}

	txId := txx.Signatures[0]
	extra := []byte{FlagConfirmCallSuccess}
	extra = append(extra, txId[:]...)
	return node.sendObserverTransactionToGroup(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeConfirmCall,
		Extra: extra,
	}, references)
}

func (node *Node) processFailedCall(ctx context.Context, call *store.SystemCall) error {
	var references []crypto.Hash
	id := common.UniqueId(call.RequestId, "confirm-fail")
	if call.Type == store.CallTypeMain {
		cid := common.UniqueId(id, "post-process")
		nonce, err := node.store.ReadSpareNonceAccount(ctx)
		if err != nil {
			panic(err)
		}
		tx := node.CreatePostprocessTransaction(ctx, call, nonce, nil, nil)
		if tx == nil {
			panic(fmt.Errorf("fail to build post-process transaction for failed call: %v", call))
		}
		err = node.store.OccupyNonceAccountByCall(ctx, nonce.Address, cid)
		if err != nil {
			return err
		}
		data, err := tx.MarshalBinary()
		if err != nil {
			panic(err)
		}
		hash, err := node.storageSubSolanaTx(ctx, cid, data)
		if err != nil {
			return err
		}
		references = append(references, hash)
	}

	nonce, err := node.store.ReadNonceAccount(ctx, call.NonceAccount)
	if err != nil {
		return err
	}
	err = node.store.ReleaseLockedNonceAccount(ctx, nonce.Address)
	if err != nil {
		return err
	}

	extra := []byte{FlagConfirmCallFail}
	extra = append(extra, uuid.Must(uuid.FromString(call.RequestId)).Bytes()...)
	return node.sendObserverTransactionToGroup(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeConfirmCall,
		Extra: extra,
	}, references)
}

func (node *Node) storageSubSolanaTx(ctx context.Context, id string, rb []byte) (crypto.Hash, error) {
	data := uuid.Must(uuid.FromString(id)).Bytes()
	data = append(data, rb...)
	if common.CheckTestEnvironment(ctx) {
		ref := crypto.Sha256Hash(data)
		return ref, node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(data))
	}
	trace := common.UniqueId(hex.EncodeToString(data), "storage-solana-tx")
	hash, err := common.WriteStorageUntilSufficient(ctx, node.mixin, data, trace, *node.SafeUser())
	if err != nil {
		return crypto.Hash{}, err
	}
	logger.Printf("observer.storageSubSolanaTx(%s) => %s", id, hash.String())
	return hash, nil
}
