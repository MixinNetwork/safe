package computer

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	mc "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/mixin/util/base58"
	"github.com/MixinNetwork/safe/apps/mixin"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/safe/mtg"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	ConfirmFlagNonceAvailable = 0
	ConfirmFlagNonceExpired   = 1

	FlagWithPostProcess = 0
	FlagSkipPostProcess = 1
)

func (node *Node) processAddUser(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleUser {
		panic(req.Role)
	}
	if req.Action != OperationTypeAddUser {
		panic(req.Action)
	}

	mix := string(req.ExtraBytes())
	_, err := bot.NewMixAddressFromString(mix)
	logger.Printf("common.NewAddressFromString(%s) => %v", mix, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}

	old, err := node.store.ReadUserByMixAddress(ctx, mix)
	logger.Printf("store.ReadUserByAddress(%s) => %v %v", mix, old, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadUserByAddress(%s) => %v", mix, err))
	} else if old != nil {
		return node.failRequest(ctx, req, "")
	}

	id, err := node.store.GetNextUserId(ctx)
	logger.Printf("store.GetNextUserId() => %s %v", id.String(), err)
	if err != nil {
		panic(err)
	}
	master, err := node.store.ReadLatestPublicKey(ctx)
	logger.Printf("store.ReadLatestPublicKey() => %s %v", master, err)
	if err != nil || master == "" {
		panic(fmt.Errorf("store.ReadLatestPublicKey() => %s %v", master, err))
	}
	public := mixin.DeriveEd25519Child(master, id.FillBytes(make([]byte, 8)))
	chainAddress := solana.PublicKeyFromBytes(public[:]).String()

	err = node.store.WriteUserWithRequest(ctx, req, id.String(), mix, chainAddress, master)
	if err != nil {
		panic(fmt.Errorf("store.WriteUserWithRequest(%v %s) => %v", req, mix, err))
	}
	return nil, ""
}

// System call operation full lifecycle:
//
//  1. user creates system call with locked nonce
//     processSystemCall
//     (state: initial, withdrawal_traces: NULL, withdrawn_at: NULL, signature: NULL)
//
//  2. observer confirms nonce available and creates prepare system call to transfer assets to user account in advance
//     mvm creates withdrawal txs and makes sign requests for user system call and prepare system call
//     processConfirmNonce
//     need withdrawals:
//     (user    system call, state: initial, withdrawal_traces: NOT NULL, withdrawn_at: NULL,     signature: NULL)
//     (prepare system call, state: initial, withdrawal_traces: "",       withdrawn_at: NOT NULL, signature: NULL)
//     otherwise:
//     (user    system call, state: pending, withdrawal_traces: "",       withdrawn_at: NOT NULL, signature: NULL)
//     (prepare system call, state: pending, withdrawal_traces: "",       withdrawn_at: NOT NULL, signature: NULL)
//
//     1). observer requests to regenerate signatures for system calls if timeout
//     processObserverRequestSign
//
//     2). mtg generate signatures for system calls
//     processSignerSignatureResponse
//     (user    system call, signature: NOT NULL)
//     (prepare system call, signature: NOT NULL)
//
//  3. observer pays the withdrawal fees and confirms all withdrawals success
//     processConfirmWithdrawal
//     (user    system call, state: pending, withdrawal_traces: "", withdrawn_at: NOT NULL, signature: NOT NULL)
//     (prepare system call, state: pending, withdrawal_traces: "", withdrawn_at: NOT NULL, signature: NOT NULL)
//
//  4. observer runs prepare system call and confirms prepare system call successfully
//     (prepare system call state: done)
//     (user    system call state: pending)
//
//  5. observer runs, confirms main call successfully
//     and creates post-process system call to transfer solana assets to mtg deposit entry and burn external assets
//     mvm makes sign requests for post-process system call
//     processConfirmCall
//     (user         system call state: done)
//     (post-process system call state: pending, withdrawal_traces: "", withdrawn_at: NOT NULL, signature: NULL)
//
//     1). mtg generate signatures for post-process system call
//     processSignerSignatureResponse
//     (prepare system call, signature: NOT NULL)
//
//  6. observer runs, confirms post-process call successfully
//     (post-process system call state: done)
func (node *Node) processSystemCall(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleUser {
		panic(req.Role)
	}
	if req.Action != OperationTypeSystemCall {
		panic(req.Action)
	}

	plan, err := node.store.ReadLatestOperationParams(ctx, req.CreatedAt)
	if err != nil {
		panic(err)
	}
	if plan == nil ||
		!plan.OperationPriceAmount.IsPositive() ||
		req.AssetId != plan.OperationPriceAsset ||
		req.Amount.Cmp(plan.OperationPriceAmount) < 0 {
		return node.failRequest(ctx, req, "")
	}

	rs, err := node.GetSystemCallReferenceTxs(ctx, req.MixinHash.String())
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	hash, err := node.store.CheckReferencesSpent(ctx, rs)
	if err != nil {
		panic(fmt.Errorf("store.CheckReferencesSpent() => %v", err))
	}
	if hash != "" {
		logger.Printf("reference %s is already spent", hash)
		return node.failRequest(ctx, req, "")
	}

	data := req.ExtraBytes()
	id := new(big.Int).SetBytes(data[:8])
	cid := uuid.Must(uuid.FromBytes(data[8:24])).String()
	skipPostprocess := false
	switch data[24] {
	case FlagSkipPostProcess:
		skipPostprocess = true
	case FlagWithPostProcess:
	default:
		logger.Printf("invalid skip postprocess flag: %d", data[24])
		return node.failRequest(ctx, req, "")
	}
	user, err := node.store.ReadUser(ctx, id)
	logger.Printf("store.ReadUser(%d) => %v %v", id, user, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadUser() => %v", err))
	} else if user == nil {
		return node.failRequest(ctx, req, "")
	}

	rb := data[25:]
	if len(rb) == 32 {
		hash := crypto.Hash(rb)
		rb = node.readStorageExtraFromObserver(ctx, hash)
	}
	call, tx, err := node.buildSystemCallFromBytes(ctx, req, cid, rb, false)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	call.Superior = call.RequestId
	call.Type = store.CallTypeMain
	call.Public = hex.EncodeToString(user.FingerprintWithPath())
	call.SkipPostprocess = skipPostprocess

	hasUser := tx.IsSigner(solana.MustPublicKeyFromBase58(user.ChainAddress))
	hasPayer := tx.IsSigner(node.solanaPayer())
	if (!hasPayer || !hasUser) && !common.CheckTestEnvironment(ctx) {
		logger.Printf("tx.IsSigner(user) => %t", hasUser)
		logger.Printf("tx.IsSigner(payer) => %t", hasPayer)
		return node.failRequest(ctx, req, "")
	}

	err = node.store.WriteInitialSystemCallWithRequest(ctx, req, call, rs)
	logger.Printf("solana.WriteInitialSystemCallWithRequest(%v %d) => %v", call, len(rs), err)
	if err != nil {
		panic(err)
	}

	return nil, ""
}

func (node *Node) processConfirmNonce(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeConfirmNonce {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	flag, extra := extra[0], extra[1:]
	callId := uuid.Must(uuid.FromBytes(extra)).String()

	call, err := node.store.ReadSystemCallByRequestId(ctx, callId, common.RequestStateInitial)
	logger.Printf("store.ReadSystemCallByRequestId(%s) => %v %v", callId, call, err)
	if err != nil {
		panic(err)
	}
	if call == nil || call.WithdrawalTraces.Valid || call.WithdrawnAt.Valid {
		return node.failRequest(ctx, req, "")
	}
	rs, err := node.GetSystemCallReferenceTxs(ctx, call.RequestHash)
	if err != nil {
		err = node.store.ExpireSystemCallWithRequest(ctx, req, call, nil, "")
		if err != nil {
			panic(err)
		}
		return nil, ""
	}
	as := node.GetSystemCallRelatedAsset(ctx, rs)

	switch flag {
	case ConfirmFlagNonceAvailable:
		prepare, tx, err := node.getSubSystemCallFromReferencedStorage(ctx, req)
		if err != nil {
			return node.failRequest(ctx, req, "")
		}
		user, err := node.store.ReadUser(ctx, call.UserIdFromPublicPath())
		logger.Printf("store.ReadUser(%s) => %v %v", call.UserIdFromPublicPath().String(), user, err)
		if err != nil {
			panic(call.RequestId)
		}
		if user == nil {
			return node.failRequest(ctx, req, "")
		}
		prepare.Superior = call.RequestId
		prepare.Type = store.CallTypePrepare
		prepare.Public = hex.EncodeToString(user.FingerprintWithEmptyPath())
		err = node.VerifySubSystemCall(ctx, tx, solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry), solana.MustPublicKeyFromBase58(user.ChainAddress))
		logger.Printf("node.VerifySubSystemCall(%s) => %v", user.ChainAddress, err)
		if err != nil {
			return node.failRequest(ctx, req, "")
		}

		var txs []*mtg.Transaction
		var ids []string
		destination := node.getMTGAddress(ctx).String()
		for _, asset := range as {
			if !asset.Solana {
				continue
			}
			id := common.UniqueId(req.Id, asset.AssetId)
			id = common.UniqueId(id, "withdrawal")
			memo := []byte(call.RequestId)
			tx := node.buildWithdrawalTransaction(ctx, req.Output, asset.AssetId, asset.Amount.String(), memo, destination, "", id)
			if tx == nil {
				return node.failRequest(ctx, req, asset.AssetId)
			}
			txs = append(txs, tx)
			ids = append(ids, tx.TraceId)
		}
		call.WithdrawalTraces = sql.NullString{Valid: true, String: strings.Join(ids, ",")}
		if len(txs) == 0 {
			call.WithdrawnAt = sql.NullTime{Valid: true, Time: req.CreatedAt}
			call.State = common.RequestStatePending
			prepare.State = common.RequestStatePending
		}

		err = node.store.ConfirmNonceAvailableWithRequest(ctx, req, call, prepare, txs, "")
		if err != nil {
			panic(err)
		}
		return txs, ""
	case ConfirmFlagNonceExpired:
		user, err := node.store.ReadUser(ctx, call.UserIdFromPublicPath())
		if err != nil || user == nil {
			panic(err)
		}
		mix, err := bot.NewMixAddressFromString(user.MixAddress)
		if err != nil {
			panic(err)
		}
		txs, compaction := node.buildRefundTxs(ctx, req, as, mix.Members(), int(mix.Threshold))
		if compaction != "" {
			return node.failRequest(ctx, req, compaction)
		}
		err = node.store.ExpireSystemCallWithRequest(ctx, req, call, txs, "")
		if err != nil {
			panic(err)
		}
		return txs, ""
	default:
		logger.Printf("invalid nonce confirm flag: %d", flag)
		return node.failRequest(ctx, req, "")
	}
}

func (node *Node) processDeployExternalAssetsCall(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeDeployExternalAssets {
		panic(req.Action)
	}

	as := make(map[string]*solanaApp.DeployedAsset)
	extra := req.ExtraBytes()
	offset := 0
	for {
		if offset == len(extra) {
			break
		}
		assetId := uuid.Must(uuid.FromBytes(extra[offset : offset+16])).String()
		offset += 16
		address := solana.PublicKeyFromBytes(extra[offset : offset+32]).String()
		offset += 32

		asset, err := common.SafeReadAssetUntilSufficient(ctx, assetId)
		if err != nil {
			panic(err)
		}
		if asset == nil || asset.ChainID == solanaApp.SolanaChainBase {
			logger.Printf("processDeployExternalAssets(%s) => invalid asset", assetId)
			return node.failRequest(ctx, req, "")
		}
		old, err := node.store.ReadDeployedAsset(ctx, assetId, 0)
		if err != nil {
			panic(err)
		}
		if old != nil {
			logger.Printf("processDeployExternalAssets(%s) => asset already existed", assetId)
			return node.failRequest(ctx, req, "")
		}
		as[address] = &solanaApp.DeployedAsset{
			AssetId: assetId,
			ChainId: asset.ChainID,
			Address: address,
			Asset:   asset,
		}
		logger.Verbosef("processDeployExternalAssets() => %s %s", assetId, address)
	}

	call, tx, err := node.getSubSystemCallFromReferencedStorage(ctx, req)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	err = node.VerifyMintSystemCall(ctx, tx, node.getMTGAddress(ctx), as)
	logger.Printf("node.VerifyMintSystemCall() => %v", err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	call.Superior = call.RequestId
	call.Type = store.CallTypeMint
	call.Public = node.getMTGPublicWithPath(ctx)
	call.State = common.RequestStatePending

	err = node.store.WriteMintCallWithRequest(ctx, req, call, as)
	logger.Printf("store.WriteMintCallWithRequest(%v) => %v", call, err)
	if err != nil {
		panic(err)
	}
	return nil, ""
}

func (node *Node) processConfirmWithdrawal(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeConfirmWithdrawal {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	txId := uuid.Must(uuid.FromBytes(extra[:16])).String()
	callId := uuid.Must(uuid.FromBytes(extra[16:32])).String()
	hash := solana.SignatureFromBytes(extra[32:]).String()

	withdrawalHash, err := common.SafeReadWithdrawalHashUntilSufficient(ctx, node.safeUser(), txId)
	logger.Printf("common.SafeReadWithdrawalHashUntilSufficient(%s) => %s %v", txId, withdrawalHash, err)
	if err != nil || withdrawalHash != hash {
		panic(err)
	}
	tx, err := node.solanaClient().RPCGetTransaction(ctx, withdrawalHash)
	logger.Printf("solana.RPCGetTransaction(%s) => %v %v", withdrawalHash, tx, err)
	if err != nil || tx == nil {
		panic(err)
	}

	call, err := node.store.ReadSystemCallByRequestId(ctx, callId, common.RequestStateInitial)
	logger.Printf("store.ReadSystemCallByRequestId(%s) => %v %v", callId, call, err)
	if err != nil {
		panic(err)
	}
	if call == nil || call.WithdrawnAt.Valid || !slices.Contains(call.GetWithdrawalIds(), txId) {
		return node.failRequest(ctx, req, "")
	}
	ids := []string{}
	for _, id := range call.GetWithdrawalIds() {
		if id == txId {
			continue
		}
		ids = append(ids, id)
	}
	call.WithdrawalTraces = sql.NullString{Valid: true, String: strings.Join(ids, ",")}
	if len(ids) == 0 {
		call.WithdrawnAt = sql.NullTime{Valid: true, Time: req.CreatedAt}
	}

	err = node.store.MarkSystemCallWithdrawnWithRequest(ctx, req, call, txId, withdrawalHash)
	if err != nil {
		panic(err)
	}
	return nil, ""
}

func (node *Node) processConfirmCall(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeConfirmCall {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	flag, extra := extra[0], extra[1:]

	var call, sub *store.SystemCall
	var assets []string
	var txs []*mtg.Transaction
	var compaction string
	switch flag {
	case FlagConfirmCallSuccess:
		signature := base58.Encode(extra[:64])
		transaction, err := node.solanaClient().RPCGetTransaction(ctx, signature)
		if err != nil {
			panic(err)
		}
		if transaction == nil {
			logger.Printf("transaction not found: %s", signature)
			return node.failRequest(ctx, req, "")
		}
		tx, err := transaction.Transaction.GetTransaction()
		if err != nil {
			panic(err)
		}
		msg, err := tx.Message.MarshalBinary()
		if err != nil {
			panic(err)
		}
		if common.CheckTestEnvironment(ctx) {
			test := getTestSystemConfirmCallMessage(signature)
			if test != nil {
				msg = test
			}
		}
		call, err = node.store.ReadSystemCallByMessage(ctx, hex.EncodeToString(msg))
		if err != nil || call == nil {
			panic(fmt.Errorf("store.ReadSystemCallByMessage(%x) => %v %v", msg, call, err))
		}
		if call.State != common.RequestStatePending {
			logger.Printf("invalid call state: %s %d", call.RequestId, call.State)
			return node.failRequest(ctx, req, "")
		}
		call.State = common.RequestStateDone
		call.Hash = sql.NullString{Valid: true, String: signature}

		switch call.Type {
		case store.CallTypeMint:
			if common.CheckTestEnvironment(ctx) {
				tx, err = solana.TransactionFromBase64(call.Raw)
				if err != nil {
					panic(err)
				}
			}
			assets = solanaApp.ExtractMintsFromTransaction(tx)
			logger.Printf("ExtractMintsFromTransaction(%v) => %v", tx, assets)
			if len(assets) == 0 {
				return node.failRequest(ctx, req, "")
			}
		case store.CallTypeMain:
			postprocess, err := node.getPostprocessCall(ctx, req, call)
			logger.Printf("node.getPostprocessCall(%v %v) => %v %v", req, call, postprocess, err)
			if err != nil {
				return node.failRequest(ctx, req, "")
			}
			if postprocess != nil {
				sub = postprocess
			}
		case store.CallTypePostProcess:
			user, err := node.store.ReadUser(ctx, call.UserIdFromPublicPath())
			if err != nil {
				panic(err)
			}
			mix, err := bot.NewMixAddressFromString(user.MixAddress)
			if err != nil {
				panic(err)
			}
			bs := solanaApp.ExtractBurnsFromTransaction(ctx, tx)
			for _, burn := range bs {
				address := burn.GetMintAccount().PublicKey.String()
				da, err := node.store.ReadDeployedAssetByAddress(ctx, address)
				if err != nil || da == nil {
					panic(err)
				}
				asset, err := common.SafeReadAssetUntilSufficient(ctx, da.AssetId)
				if err != nil {
					panic(err)
				}
				amount := decimal.New(int64(*burn.Amount), -int32(asset.Precision))
				dust, err := decimal.NewFromString(asset.Dust)
				if err != nil {
					panic(err)
				}
				if amount.Cmp(dust) < 0 {
					logger.Printf("skip burned asset: %s %s", da.AssetId, amount.String())
					continue
				}
				id := common.UniqueId(call.RequestId, fmt.Sprintf("refund-burn-asset:%s", da.AssetId))
				id = common.UniqueId(id, user.MixAddress)
				tx := node.buildTransaction(ctx, req.Output, node.conf.AppId, da.AssetId, mix.Members(), int(mix.Threshold), amount.String(), []byte("refund"), id)
				if tx == nil {
					compaction = da.AssetId
					txs = nil
					break
				}
				txs = append(txs, tx)
			}
		}

	case FlagConfirmCallFail:
		callId := uuid.Must(uuid.FromBytes(extra)).String()
		c, err := node.store.ReadSystemCallByRequestId(ctx, callId, common.RequestStatePending)
		logger.Printf("store.ReadSystemCallByRequestId(%s) => %v %v", callId, c, err)
		if err != nil {
			panic(err)
		}
		if c == nil {
			return node.failRequest(ctx, req, "")
		}
		call = c
		call.State = common.RequestStateFailed

		postprocess, err := node.getPostprocessCall(ctx, req, call)
		logger.Printf("node.getPostprocessCall(%v %v) => %v %v", req, call, postprocess, err)
		if err != nil {
			return node.failRequest(ctx, req, "")
		}
		if postprocess != nil {
			sub = postprocess
		}
	default:
		logger.Printf("invalid confirm flag: %d", flag)
		return node.failRequest(ctx, req, "")
	}

	err := node.store.ConfirmSystemCallWithRequest(ctx, req, call, sub, assets, txs, compaction)
	if err != nil {
		panic(err)
	}
	return txs, compaction
}

func (node *Node) processObserverRequestSign(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeSignInput {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	callId := uuid.Must(uuid.FromBytes(extra[:16])).String()
	call, err := node.store.ReadSystemCallByRequestId(ctx, callId, 0)
	logger.Printf("store.ReadSystemCallByRequestId(%s) => %v %v", callId, call, err)
	if err != nil {
		panic(err)
	}
	if call == nil || call.Signature.Valid || call.State == common.RequestStateFailed {
		return node.failRequest(ctx, req, "")
	}
	old, err := node.store.ReadSession(ctx, req.Id)
	logger.Printf("store.ReadSession(%s) => %v %v", req.Id, old, err)
	if err != nil {
		panic(err)
	}
	if old != nil {
		return node.failRequest(ctx, req, "")
	}

	session := &store.Session{
		Id:         req.Id,
		RequestId:  call.RequestId,
		MixinHash:  req.MixinHash.String(),
		MixinIndex: req.Output.OutputIndex,
		Index:      0,
		Operation:  OperationTypeSignInput,
		Public:     call.Public,
		Extra:      call.Message,
		CreatedAt:  req.CreatedAt,
	}
	err = node.store.WriteSignSessionWithRequest(ctx, req, call, []*store.Session{session})
	if err != nil {
		panic(err)
	}
	return nil, ""
}

// create system call to transfer assets to mtg deposit entry from user account on Solana
func (node *Node) processObserverCreateDepositCall(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	logger.Printf("node.processObserverCreateDepositCall(%s)", string(node.id))
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeDeposit {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	userAddress := solana.PublicKeyFromBytes(extra[:32])
	signature := solana.SignatureFromBytes(extra[32:])

	user, err := node.store.ReadUserByChainAddress(ctx, userAddress.String())
	logger.Printf("store.ReadUserByChainAddress(%s) => %v %v", userAddress.String(), user, err)
	if err != nil {
		panic(err)
	}
	if user == nil {
		return node.failRequest(ctx, req, "")
	}
	// TODO should compare built tx and deposit tx from signature
	txx, err := node.solanaClient().RPCGetTransaction(ctx, signature.String())
	if err != nil {
		panic(fmt.Errorf("rpc.RPCGetTransaction(%s) => %v %v", signature.String(), txx, err))
	}
	if txx == nil {
		return node.failRequest(ctx, req, "")
	}

	call, tx, err := node.getSubSystemCallFromReferencedStorage(ctx, req)
	if err != nil {
		logger.Printf("node.getSubSystemCallFromReferencedStorage(%v) => %v", req, err)
		return node.failRequest(ctx, req, "")
	}
	err = node.VerifySubSystemCall(ctx, tx, solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry), userAddress)
	logger.Printf("node.VerifySubSystemCall(%s %s) => %v", node.conf.SolanaDepositEntry, userAddress, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	call.Superior = call.RequestId
	call.Type = store.CallTypeMain
	call.Public = hex.EncodeToString(user.FingerprintWithPath())
	call.State = common.RequestStatePending

	err = node.store.WriteSubCallWithRequest(ctx, req, call)
	if err != nil {
		panic(err)
	}

	return nil, ""
}

// deposit from Solana to mtg deposit entry
func (node *Node) processDeposit(ctx context.Context, out *mtg.Action) ([]*mtg.Transaction, string) {
	logger.Printf("node.processDeposit(%v)", out)
	ar, handled, err := node.store.ReadActionResult(ctx, out.OutputId, out.OutputId)
	logger.Printf("store.ReadActionResult(%s %s) => %v %t %v", out.OutputId, out.OutputId, ar, handled, err)
	if err != nil {
		panic(err)
	}
	if ar != nil {
		return ar.Transactions, ar.Compaction
	}
	if handled {
		err = node.store.FailAction(ctx, &store.Request{
			Id:     out.OutputId,
			Output: out,
		})
		if err != nil {
			panic(err)
		}
		return nil, ""
	}

	ver, err := common.VerifyKernelTransaction(ctx, node.group, out, time.Minute)
	if err != nil {
		panic(err)
	}
	deposit := ver.DepositData()

	rpcTx, err := node.solanaClient().RPCGetTransaction(ctx, deposit.Transaction)
	if err != nil {
		panic(err)
	}
	tx, err := rpcTx.Transaction.GetTransaction()
	if err != nil {
		panic(err)
	}
	ts, err := node.solanaClient().ExtractTransfersFromTransaction(ctx, tx, rpcTx.Meta, nil)
	if err != nil {
		panic(err)
	}

	var txs []*mtg.Transaction
	var compaction string
	for i, t := range ts {
		logger.Printf("%d-th transfer: %v", i, t)
		if t.AssetId != out.AssetId {
			continue
		}
		if t.Receiver != node.solanaDepositEntry().String() {
			continue
		}
		asset, err := common.SafeReadAssetUntilSufficient(ctx, t.AssetId)
		if err != nil {
			panic(err)
		}
		expected := mc.NewIntegerFromString(decimal.NewFromBigInt(t.Value, -int32(asset.Precision)).String())
		actual := mc.NewIntegerFromString(out.Amount.String())
		if expected.Cmp(actual) != 0 {
			panic(fmt.Errorf("invalid deposit amount: %s %s", expected.String(), actual.String()))
		}
		user, err := node.store.ReadUserByChainAddress(ctx, t.Sender)
		logger.Verbosef("store.ReadUserByAddress(%s) => %v %v", t.Sender, user, err)
		if err != nil {
			panic(err)
		} else if user == nil {
			continue
		}
		mix, err := bot.NewMixAddressFromString(user.MixAddress)
		if err != nil {
			panic(err)
		}
		id := common.UniqueId(deposit.Transaction, fmt.Sprintf("deposit-%d", i))
		id = common.UniqueId(id, t.Receiver)
		tx := node.buildTransaction(ctx, out, node.conf.AppId, t.AssetId, mix.Members(), int(mix.Threshold), out.Amount.String(), []byte("deposit"), id)
		if tx == nil {
			compaction = t.AssetId
			txs = nil
			break
		}
		txs = append(txs, tx)
	}

	state := common.RequestStateDone
	if compaction != "" {
		state = common.RequestStateFailed
	}
	err = node.store.WriteDepositRequestIfNotExist(ctx, out, state, txs, compaction)
	logger.Printf("store.WriteDepositRequestIfNotExist(%v %d %d %s) => %v", out, state, len(txs), compaction, err)
	if err != nil {
		panic(err)
	}

	return txs, compaction
}

func (node *Node) getPostprocessCall(ctx context.Context, req *store.Request, call *store.SystemCall) (*store.SystemCall, error) {
	if call.Type != store.CallTypeMain {
		return nil, nil
	}
	if !common.CheckTestEnvironment(ctx) {
		ver, err := common.VerifyKernelTransaction(ctx, node.group, req.Output, KernelTimeout)
		if err != nil {
			panic(err)
		}
		if len(ver.References) != 1 {
			return nil, nil
		}
	}

	postprocess, tx, err := node.getSubSystemCallFromReferencedStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	postprocess.Superior = call.RequestId
	postprocess.Type = store.CallTypePostProcess
	postprocess.Public = call.Public
	postprocess.State = common.RequestStatePending

	user, err := node.store.ReadUser(ctx, call.UserIdFromPublicPath())
	if err != nil {
		panic(err)
	}
	if user == nil {
		return nil, fmt.Errorf("store.ReadUser(%s) => nil", call.UserIdFromPublicPath().String())
	}
	err = node.VerifySubSystemCall(ctx, tx, solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry), solana.MustPublicKeyFromBase58(user.ChainAddress))
	logger.Printf("node.VerifySubSystemCall(%s) => %v", user.ChainAddress, err)
	if err != nil {
		return nil, err
	}
	return postprocess, nil
}

func (node *Node) getSubSystemCallFromReferencedStorage(ctx context.Context, req *store.Request) (*store.SystemCall, *solana.Transaction, error) {
	var references []crypto.Hash
	if common.CheckTestEnvironment(ctx) {
		references = outputReferences[req.Output.OutputId]
	} else {
		ver, err := common.VerifyKernelTransaction(ctx, node.group, req.Output, KernelTimeout)
		if err != nil {
			panic(err)
		}
		if len(ver.References) != 1 {
			return nil, nil, fmt.Errorf("invalid count of references from request: %v %v", req, ver)
		}
		references = ver.References
	}
	data := node.readStorageExtraFromObserver(ctx, references[0])
	id, raw := uuid.Must(uuid.FromBytes(data[:16])).String(), data[16:]
	return node.buildSystemCallFromBytes(ctx, req, id, raw, true)
}

// should only return error when fail to parse nonce advance instruction;
// without fields of superior, type, public, skip_postprocess
func (node *Node) buildSystemCallFromBytes(ctx context.Context, req *store.Request, id string, raw []byte, withdrawn bool) (*store.SystemCall, *solana.Transaction, error) {
	tx, err := solana.TransactionFromBytes(raw)
	logger.Printf("solana.TransactionFromBytes(%x) => %v %v", raw, tx, err)
	if err != nil {
		panic(err)
	}
	err = node.solanaClient().ProcessTransactionWithAddressLookups(ctx, tx)
	if err != nil {
		panic(err)
	}
	advance, err := solanaApp.NonceAccountFromTx(tx)
	logger.Printf("solana.NonceAccountFromTx() => %v %v", advance, err)
	if err != nil {
		return nil, nil, err
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		panic(err)
	}
	call := &store.SystemCall{
		RequestId:    id,
		RequestHash:  req.MixinHash.String(),
		NonceAccount: advance.GetNonceAccount().PublicKey.String(),
		Message:      hex.EncodeToString(msg),
		Raw:          tx.MustToBase64(),
		State:        common.RequestStateInitial,
		CreatedAt:    req.CreatedAt,
		UpdatedAt:    req.CreatedAt,
	}
	if withdrawn {
		call.WithdrawalTraces = sql.NullString{Valid: true, String: ""}
		call.WithdrawnAt = sql.NullTime{Valid: true, Time: req.CreatedAt}
	}
	return call, tx, nil
}
