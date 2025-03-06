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
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/mixin/util/base58"
	"github.com/MixinNetwork/safe/apps/mixin"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
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
//     (state: initial, withdrawal_traces: NULL, withdrawn_at: NULL)
//
//  2. observer confirms nonce available and make mtg create withdrawal txs
//     processConfirmNonce
//     (state: initial, withdrawal_traces: NOT NULL, withdrawn_at: NULL)
//
//  3. observer pays the withdrawal fees and confirms all withdrawals success to mtg
//     processConfirmWithdrawal
//     (state: initial, withdrawal_traces: "", withdrawn_at: NOT NULL)
//
//  4. observer creates, runs and confirms sub prepare system call to transfer or mint assets to user account
//     processCreateSubCall
//     (state: pending, signature: NULL)
//
//  5. observer requests to generate signature for main call
//     processObserverRequestSign
//     (state: pending, signature: NOT NULL)
//
//  6. observer runs and confirms main call success
//     processConfirmCall
//     (state: done, signature: NOT NULL)
//
//  7. observer create postprocess system call to deposit solana assets to mtg and burn external assets
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

	rs, err := node.GetSystemCallReferenceTxs(ctx, req.Id)
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
	skipPostprocess := false
	switch data[8] {
	case FlagSkipPostProcess:
		skipPostprocess = true
	case FlagWithPostProcess:
	default:
		logger.Printf("invalid skip postprocess flag: %d", data[8])
		return node.failRequest(ctx, req, "")
	}
	user, err := node.store.ReadUser(ctx, id)
	logger.Printf("store.ReadUser(%d) => %v %v", id, user, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadUser() => %v", err))
	} else if user == nil {
		return node.failRequest(ctx, req, "")
	}

	rb := data[9:]
	if len(rb) == 32 {
		hash := crypto.Hash(rb)
		rb = node.readStorageExtraFromObserver(ctx, hash)
	}
	tx, err := solana.TransactionFromBytes(rb)
	logger.Printf("solana.TransactionFromBytes(%x) => %v %v", rb, tx, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	hasUser := tx.IsSigner(solana.MustPublicKeyFromBase58(user.ChainAddress))
	hasPayer := tx.IsSigner(node.solanaPayer())
	if (!hasPayer || !hasUser) && !common.CheckTestEnvironment(ctx) {
		logger.Printf("tx.IsSigner(user) => %t", hasUser)
		logger.Printf("tx.IsSigner(payer) => %t", hasPayer)
		return node.failRequest(ctx, req, "")
	}

	err = node.solanaClient().ProcessTransactionWithAddressLookups(ctx, tx)
	if err != nil {
		panic(err)
	}
	advance, err := solanaApp.NonceAccountFromTx(tx)
	logger.Printf("solana.NonceAccountFromTx() => %v %v", advance, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		logger.Printf("solana.MarshalBinary() => %v", err)
		return node.failRequest(ctx, req, "")
	}
	call := &store.SystemCall{
		RequestId:       req.Id,
		Superior:        req.Id,
		Type:            store.CallTypeMain,
		NonceAccount:    advance.GetNonceAccount().PublicKey.String(),
		Public:          hex.EncodeToString(user.FingerprintWithPath()),
		SkipPostprocess: skipPostprocess,
		Message:         hex.EncodeToString(msg),
		Raw:             tx.MustToBase64(),
		State:           common.RequestStateInitial,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}

	err = node.store.WriteInitialSystemCallWithRequest(ctx, req, call, rs, nil, "")
	logger.Printf("solana.WriteInitialSystemCallWithRequest(%v) => %v", call, err)
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
	rs, err := node.GetSystemCallReferenceTxs(ctx, req.Id)
	if err != nil {
		err = node.store.ConfirmSystemCallFailWithRequest(ctx, req, call, nil)
		if err != nil {
			panic(err)
		}
		return nil, ""
	}
	as := node.GetSystemCallRelatedAsset(ctx, rs)

	switch flag {
	case ConfirmFlagNonceAvailable:
		var txs []*mtg.Transaction
		var ids []string
		destination := node.getMTGAddress(ctx).String()
		for _, asset := range as {
			if !asset.Solana {
				continue
			}
			id := common.UniqueId(req.Id, asset.Asset.AssetID)
			id = common.UniqueId(id, "withdrawal")
			memo := []byte(req.Id)
			tx := node.buildWithdrawalTransaction(ctx, req.Output, asset.Asset.AssetID, asset.Amount.String(), memo, destination, "", id)
			if tx == nil {
				return node.failRequest(ctx, req, asset.Asset.AssetID)
			}
			txs = append(txs, tx)
			ids = append(ids, tx.TraceId)
		}
		call.WithdrawalTraces = sql.NullString{Valid: true, String: strings.Join(ids, ",")}
		if len(txs) == 0 {
			call.WithdrawnAt = sql.NullTime{Valid: true, Time: req.CreatedAt}
		}

		err = node.store.UpdateWithdrawalsWithRequest(ctx, req, call, txs, "")
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
		err = node.store.ConfirmSystemCallFailWithRequest(ctx, req, call, txs)
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

	extra := req.ExtraBytes()
	if len(extra) < 96 {
		logger.Printf("invalid extra length: %x", extra)
		return node.failRequest(ctx, req, "")
	}
	cid := uuid.Must(uuid.FromBytes(extra[:16])).String()
	hash, err := crypto.HashFromString(hex.EncodeToString(extra[16:48]))
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	as := make(map[string]*solanaApp.DeployedAsset)
	offset := 48
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
			Address: address,
			Asset:   asset,
		}
		logger.Verbosef("processDeployExternalAssets() => %s %s", assetId, address)
	}

	raw := node.readStorageExtraFromObserver(ctx, hash)
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
		return node.failRequest(ctx, req, "")
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		panic(err)
	}
	err = node.VerifyMintSystemCall(ctx, tx, node.getMTGAddress(ctx), as)
	logger.Printf("node.VerifyMintSystemCall() => %v", err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}

	call := &store.SystemCall{
		RequestId:        cid,
		Superior:         cid,
		Type:             store.CallTypeMint,
		NonceAccount:     advance.GetNonceAccount().PublicKey.String(),
		Public:           node.getMTGPublicWithPath(ctx),
		Message:          hex.EncodeToString(msg),
		Raw:              tx.MustToBase64(),
		State:            common.RequestStatePending,
		WithdrawalTraces: sql.NullString{Valid: true, String: ""},
		WithdrawnAt:      sql.NullTime{Valid: true, Time: req.CreatedAt},
		CreatedAt:        req.CreatedAt,
		UpdatedAt:        req.CreatedAt,
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
	err = node.store.WriteMintCallWithRequest(ctx, req, call, session, as)
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
	reqId := uuid.Must(uuid.FromBytes(extra[16:32])).String()
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

	call, err := node.store.ReadSystemCallByRequestId(ctx, reqId, common.RequestStateInitial)
	logger.Printf("store.ReadSystemCallByRequestId(%s) => %v %v", reqId, call, err)
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

func (node *Node) processCreateSubCall(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeCreateSubCall {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	callId := uuid.Must(uuid.FromBytes(extra[:16])).String()
	mainId := uuid.Must(uuid.FromBytes(extra[16:32])).String()
	hash, err := crypto.HashFromString(hex.EncodeToString(extra[32:64]))
	if err != nil {
		panic(err)
	}

	call, err := node.store.ReadSystemCallByRequestId(ctx, mainId, 0)
	logger.Printf("store.ReadSystemCallByRequestId(%s) => %v %v", mainId, call, err)
	if err != nil {
		panic(mainId)
	}
	if call == nil {
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

	raw := node.readStorageExtraFromObserver(ctx, hash)
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
		return node.failRequest(ctx, req, "")
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		panic(err)
	}
	err = node.VerifySubSystemCall(ctx, tx, solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry), solana.MustPublicKeyFromBase58(user.ChainAddress))
	logger.Printf("node.VerifySubSystemCall(%s) => %v", user.ChainAddress, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}

	sub := &store.SystemCall{
		RequestId:        callId,
		Superior:         call.RequestId,
		NonceAccount:     advance.GetNonceAccount().PublicKey.String(),
		Message:          hex.EncodeToString(msg),
		Raw:              tx.MustToBase64(),
		State:            common.RequestStatePending,
		WithdrawalTraces: sql.NullString{Valid: true, String: ""},
		WithdrawnAt:      sql.NullTime{Valid: true, Time: req.CreatedAt},
		CreatedAt:        req.CreatedAt,
		UpdatedAt:        req.CreatedAt,
	}
	switch call.State {
	case common.RequestStateInitial:
		sub.Public = hex.EncodeToString(user.FingerprintWithEmptyPath())
		sub.Type = store.CallTypePrepare
	case common.RequestStateDone, common.RequestStateFailed:
		sub.Public = call.Public
		sub.Type = store.CallTypePostProcess
	default:
		panic(req)
	}

	err = node.store.WriteSubCallWithRequest(ctx, req, sub, nil, "")
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
	switch flag {
	case FlagConfirmCallSuccess:
		signature := base58.Encode(extra[:64])
		_ = solana.MustSignatureFromBase58(signature)

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
		call, err := node.store.ReadSystemCallByMessage(ctx, hex.EncodeToString(msg))
		if err != nil || call == nil {
			panic(fmt.Errorf("store.ReadSystemCallByMessage(%x) => %v %v", msg, call, err))
		}
		if call.State != common.RequestStatePending {
			logger.Printf("invalid call state: %s %d", call.RequestId, call.State)
			return node.failRequest(ctx, req, "")
		}

		var assets []string
		var txs []*mtg.Transaction
		var compaction string
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
		case store.CallTypePostProcess:
			bs := solanaApp.ExtractBurnsFromTransaction(ctx, tx)
			if len(bs) == 0 {
				panic(fmt.Errorf("invalid burned assets length: %s %d", call.RequestId, len(bs)))
			}
			user, err := node.store.ReadUser(ctx, call.UserIdFromPublicPath())
			if err != nil {
				panic(err)
			}
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
				id := common.UniqueId(call.RequestId, fmt.Sprintf("refund-burn-asset:%s", da.AssetId))
				id = common.UniqueId(id, user.MixAddress)
				tx := node.buildTransaction(ctx, req.Output, node.conf.AppId, da.AssetId, []string{user.MixAddress}, 1, amount.String(), []byte("refund"), id)
				if tx == nil {
					compaction = da.AssetId
					txs = nil
					break
				}
				txs = append(txs, tx)
			}
		}

		err = node.store.ConfirmSystemCallSuccessWithRequest(ctx, req, call, assets, txs, compaction)
		if err != nil {
			panic(err)
		}
		return txs, compaction
	case FlagConfirmCallFail:
		callId := uuid.Must(uuid.FromBytes(extra)).String()
		call, err := node.store.ReadSystemCallByRequestId(ctx, callId, common.RequestStatePending)
		if err != nil || call == nil {
			panic(err)
		}
		user, err := node.store.ReadUser(ctx, call.UserIdFromPublicPath())
		if err != nil || user == nil {
			panic(err)
		}
		mix, err := bot.NewMixAddressFromString(user.MixAddress)
		if err != nil {
			panic(err)
		}

		rs, err := node.GetSystemCallReferenceTxs(ctx, req.Id)
		if err != nil {
			err = node.store.ConfirmSystemCallFailWithRequest(ctx, req, call, nil)
			if err != nil {
				panic(err)
			}
			return nil, ""
		}
		as := node.GetSystemCallRelatedAsset(ctx, rs)
		txs, compaction := node.buildRefundTxs(ctx, req, as, mix.Members(), int(mix.Threshold))
		if compaction != "" {
			return node.failRequest(ctx, req, compaction)
		}
		err = node.store.ConfirmSystemCallFailWithRequest(ctx, req, call, txs)
		if err != nil {
			panic(err)
		}
		return txs, ""
	default:
		logger.Printf("invalid confirm flag: %d", flag)
		return node.failRequest(ctx, req, "")
	}
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
	call, err := node.store.ReadSystemCallByRequestId(ctx, callId, common.RequestStatePending)
	logger.Printf("store.ReadSystemCallByRequestId(%s) => %v %v", callId, call, err)
	if err != nil {
		panic(err)
	}
	if call == nil {
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
	nonceAccount := solana.PublicKeyFromBytes(extra[32:64]).String()
	hash, err := crypto.HashFromString(hex.EncodeToString(extra[64:96]))
	if err != nil {
		panic(err)
	}

	user, err := node.store.ReadUserByChainAddress(ctx, userAddress.String())
	logger.Printf("store.ReadUserByChainAddress(%s) => %v %v", userAddress.String(), user, err)
	if err != nil {
		panic(err)
	}
	if user == nil {
		return node.failRequest(ctx, req, "")
	}

	raw := node.readStorageExtraFromObserver(ctx, hash)
	tx, err := solana.TransactionFromBytes(raw)
	logger.Printf("solana.TransactionFromBytes(%x) => %v %v", raw, tx, err)
	if err != nil {
		panic(err)
	}

	err = node.VerifySubSystemCall(ctx, tx, solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry), userAddress)
	logger.Printf("node.VerifySubSystemCall(%s %s) => %v", node.conf.SolanaDepositEntry, userAddress, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}

	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		panic(err)
	}
	new := &store.SystemCall{
		RequestId:        req.Id,
		Superior:         req.Id,
		Type:             store.CallTypeMain,
		Public:           hex.EncodeToString(user.FingerprintWithPath()),
		NonceAccount:     nonceAccount,
		Message:          hex.EncodeToString(msg),
		Raw:              tx.MustToBase64(),
		State:            common.RequestStatePending,
		WithdrawalTraces: sql.NullString{Valid: true, String: ""},
		WithdrawnAt:      sql.NullTime{Valid: true, Time: req.CreatedAt},
		Signature:        sql.NullString{Valid: false},
		RequestSignerAt:  sql.NullTime{Valid: false},
		CreatedAt:        req.CreatedAt,
		UpdatedAt:        req.CreatedAt,
	}

	err = node.store.WriteSubCallWithRequest(ctx, req, new, nil, "")
	if err != nil {
		panic(err)
	}

	return nil, ""
}

func (node *Node) processDeposit(ctx context.Context, out *mtg.Action) ([]*mtg.Transaction, string) {
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
	ts, err := node.solanaClient().ExtractTransfersFromTransaction(ctx, tx, rpcTx.Meta)
	if err != nil {
		panic(err)
	}

	var txs []*mtg.Transaction
	var compaction string
	for i, t := range ts {
		if t.Receiver != node.solanaDepositEntry().String() {
			continue
		}
		user, err := node.store.ReadUserByChainAddress(ctx, t.Receiver)
		logger.Verbosef("store.ReadUserByAddress(%s) => %v %v", t.Receiver, user, err)
		if err != nil {
			panic(err)
		} else if user == nil {
			continue
		}
		asset := solanaApp.GenerateAssetId(t.TokenAddress)
		id := common.UniqueId(deposit.Transaction, fmt.Sprintf("deposit-%d", i))
		id = common.UniqueId(id, t.Receiver)
		tx := node.buildTransaction(ctx, out, node.conf.AppId, asset, []string{user.MixAddress}, 1, t.Value.String(), []byte("deposit"), id)
		if tx == nil {
			compaction = asset
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
	if err != nil {
		panic(err)
	}

	return txs, compaction
}
