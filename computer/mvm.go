package computer

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
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
	"github.com/MixinNetwork/trusted-group/mtg"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	ConfirmFlagMixinWithdrawal = 0
	ConfirmFlagOnChainTx       = 1

	ConfirmFlagNonceAvailable = 0
	ConfirmFlagNonceExpired   = 1
)

func (node *Node) processAddUser(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleUser {
		panic(req.Role)
	}
	if req.Action != OperationTypeAddUser {
		panic(req.Action)
	}

	mix := string(req.ExtraBytes())
	_, err := mc.NewAddressFromString(mix)
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
	key, err := node.store.ReadLatestKey(ctx)
	logger.Printf("store.ReadLatestKey() => %s %v", key, err)
	if err != nil || key == "" {
		panic(fmt.Errorf("store.ReadLatestKey() => %s %v", key, err))
	}
	public := mixin.DeriveEd25519Child(key, id.FillBytes(make([]byte, 8)))
	chainAddress := solana.PublicKeyFromBytes(public[:]).String()

	err = node.store.WriteUserWithRequest(ctx, req, id.String(), mix, chainAddress, key)
	if err != nil {
		panic(fmt.Errorf("store.WriteUserWithRequest(%v %s) => %v", req, mix, err))
	}
	return nil, ""
}

// simplified steps:
//  1. user creates system call with locked nonce
//     (state: initial, withdrawal_traces: NULL, withdrawn_at: NULL)
//  2. observer confirms nonce available and make mtg create withdrawal txs
//     (state: initial, withdrawal_traces: NOT NULL, withdrawn_at: NULL)
//  3. observer pays the withdrawal fees and confirms all withdrawals success to mtg
//     (state: initial, withdrawal_traces: "", withdrawn_at: NOT NULL)
//  4. observer creates, runs and confirms sub prepare system call to transfer or mint assets to user account
//     (state: pending, signature: NULL)
//  5. observer requests to generate signature for main call
//     (state: pending, signature: NOT NULL)
//  6. observer runs and confirms main call success
//     (state: done, signature: NOT NULL)
//  7. observer create postprocess system call to deposit solana assets to mtg and burn external assets
func (node *Node) processSystemCall(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleUser {
		panic(req.Role)
	}
	if req.Action != OperationTypeSystemCall {
		panic(req.Action)
	}

	data := req.ExtraBytes()
	id := new(big.Int).SetBytes(data[:8])
	user, err := node.store.ReadUser(ctx, id)
	logger.Printf("store.ReadUser(%d) => %v %v", id, user, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadUser() => %v", err))
	} else if user == nil {
		return node.failRequest(ctx, req, "")
	}

	plan, err := node.store.ReadLatestOperationParams(ctx, req.CreatedAt)
	if err != nil {
		panic(err)
	}
	if plan == nil || !plan.OperationPriceAmount.IsPositive() {
		mix, err := bot.NewMixAddressFromString(user.MixAddress)
		if err != nil {
			panic(err)
		}
		return node.refundAndFailRequest(ctx, req, mix.Members(), int(mix.Threshold))
	}
	if req.AssetId != plan.OperationPriceAsset || req.Amount.Cmp(plan.OperationPriceAmount) < 0 {
		return node.failRequest(ctx, req, "")
	}

	tx, err := solana.TransactionFromBytes(data[8:])
	logger.Printf("solana.TransactionFromBytes(%x) => %v %v", data[8:], tx, err)
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

	advance, flag := solanaApp.NonceAccountFromTx(tx)
	logger.Printf("solana.NonceAccountFromTx() => %v %t", advance, flag)
	if !flag {
		return node.failRequest(ctx, req, "")
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		panic(err)
	}
	call := &store.SystemCall{
		RequestId:    req.Id,
		Superior:     req.Id,
		Type:         store.CallTypeMain,
		NonceAccount: advance.GetNonceAccount().PublicKey.String(),
		Public:       hex.EncodeToString(user.FingerprintWithPath()),
		Message:      hex.EncodeToString(msg),
		Raw:          tx.MustToBase64(),
		State:        common.RequestStateInitial,
		CreatedAt:    req.CreatedAt,
		UpdatedAt:    req.CreatedAt,
	}

	err = node.store.WriteInitialSystemCallWithRequest(ctx, req, call, nil, "")
	logger.Printf("solana.WriteInitialSystemCallWithRequest(%v) => %v", call, err)
	if err != nil {
		panic(err)
	}

	return nil, ""
}

func (node *Node) processSetOperationParams(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeSetOperationParams {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	if len(extra) != 24 {
		return node.failRequest(ctx, req, "")
	}

	assetId := uuid.Must(uuid.FromBytes(extra[:16]))
	abu := new(big.Int).SetUint64(binary.BigEndian.Uint64(extra[16:24]))
	amount := decimal.NewFromBigInt(abu, -8)
	params := &store.OperationParams{
		RequestId:            req.Id,
		OperationPriceAsset:  assetId.String(),
		OperationPriceAmount: amount,
		CreatedAt:            req.CreatedAt,
	}
	err := node.store.WriteOperationParamsFromRequest(ctx, params, req)
	if err != nil {
		panic(err)
	}
	return nil, ""
}

func (node *Node) processSignerKeygenRequests(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeKeygenInput {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	if len(extra) != 1 {
		return node.failRequest(ctx, req, "")
	}
	count, err := node.store.CountKeys(ctx)
	logger.Printf("store.CountKeys() => %v %d:%d:%d", err, count, extra[0], node.conf.MpcKeyNumber)
	if err != nil {
		panic(err)
	}
	if int(extra[0]) != count || count >= node.conf.MpcKeyNumber {
		return node.failRequest(ctx, req, "")
	}

	members := node.GetMembers()
	threshold := node.conf.MTG.Genesis.Threshold
	id := common.UniqueId(req.Id, fmt.Sprintf("OperationTypeKeygenInput:%d", count))
	id = common.UniqueId(id, fmt.Sprintf("MTG:%v:%d", members, threshold))
	sessions := []*store.Session{{
		Id:         id,
		RequestId:  req.Id,
		MixinHash:  req.MixinHash.String(),
		MixinIndex: req.Output.OutputIndex,
		Index:      0,
		Operation:  OperationTypeKeygenInput,
		CreatedAt:  req.CreatedAt,
	}}
	err = node.store.WriteSessionsWithRequest(ctx, req, sessions, false)
	if err != nil {
		panic(fmt.Errorf("store.WriteSessionsWithRequest(%v) => %v", req, err))
	}
	return nil, ""
}

func (node *Node) processSignerKeygenResults(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleSigner {
		panic(req.Role)
	}
	if req.Action != OperationTypeKeygenOutput {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	sid := uuid.FromBytesOrNil(extra[:16]).String()
	public := extra[16:]

	s, err := node.store.ReadSession(ctx, sid)
	logger.Printf("store.ReadSession(%s) => %v %v", sid, s, err)
	if err != nil {
		panic(err)
	}
	if s == nil {
		return node.failRequest(ctx, req, "")
	}
	fp := hex.EncodeToString(common.Fingerprint(hex.EncodeToString(public)))
	key, _, err := node.store.ReadKeyByFingerprint(ctx, fp)
	logger.Printf("store.ReadKeyByFingerprint(%s) => %s %v", fp, key, err)
	if err != nil {
		panic(err)
	}
	if key != hex.EncodeToString(public) || key == "" {
		return node.failRequest(ctx, req, "")
	}

	sender := req.Output.Senders[0]
	err = node.store.WriteSessionSignerIfNotExist(ctx, s.Id, sender, public, req.Output.SequencerCreatedAt, sender == string(node.id))
	if err != nil {
		panic(fmt.Errorf("store.WriteSessionSignerIfNotExist(%v) => %v", s, err))
	}
	signers, err := node.store.ListSessionSignerResults(ctx, s.Id)
	if err != nil {
		panic(fmt.Errorf("store.ListSessionSignerResults(%s) => %d %v", s.Id, len(signers), err))
	}
	finished, sig := node.verifySessionSignerResults(ctx, s, signers)
	logger.Printf("node.verifySessionSignerResults(%v, %d) => %t %x", s, len(signers), finished, sig)
	if !finished {
		return node.failRequest(ctx, req, "")
	}
	if l := len(signers); l <= node.threshold {
		panic(s.Id)
	}

	valid := node.verifySessionHolder(ctx, hex.EncodeToString(public))
	logger.Printf("node.verifySessionHolder(%x) => %t", public, valid)
	if !valid {
		return nil, ""
	}

	err = node.store.MarkKeyConfirmedWithRequest(ctx, req, hex.EncodeToString(public))
	if err != nil {
		panic(fmt.Errorf("store.MarkKeyConfirmedWithRequest(%v) => %v", req, err))
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

	switch flag {
	case ConfirmFlagNonceAvailable:
		var txs []*mtg.Transaction
		var ids []string
		as := node.getSystemCallRelatedAsset(ctx, callId)
		destination := node.getMtgAddress(ctx).String()
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
		return node.refundAndFailRequest(ctx, req, mix.Members(), int(mix.Threshold))
	default:
		logger.Printf("invalid nonce confirm flag: %d", flag)
		return node.failRequest(ctx, req, "")
	}
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

	err = node.store.MarkSystemCallWithdrewWithRequest(ctx, req, call, txId, withdrawalHash)
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
	reqId := uuid.Must(uuid.FromBytes(extra[:16])).String()
	hash, err := crypto.HashFromString(hex.EncodeToString(extra[16:48]))
	if err != nil {
		panic(err)
	}
	extra = extra[48:]
	var offset int
	var as []*store.DeployedAsset
	for {
		if offset == len(extra) {
			break
		}
		asset := uuid.Must(uuid.FromBytes(extra[offset : offset+16])).String()
		offset += 16
		address := solana.PublicKeyFromBytes(extra[offset : offset+32]).String()
		offset += 32
		as = append(as, &store.DeployedAsset{
			AssetId: asset,
			Address: address,
		})
	}

	call, err := node.store.ReadSystemCallByRequestId(ctx, reqId, 0)
	logger.Printf("store.ReadSystemCallByRequestId(%s) => %v %v", reqId, call, err)
	if err != nil {
		panic(reqId)
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
	advance, flag := solanaApp.NonceAccountFromTx(tx)
	logger.Printf("solana.NonceAccountFromTx() => %v %t", advance, flag)
	if !flag {
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
		RequestId:        req.Id,
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

	err = node.store.WriteSubCallAndAssetsWithRequest(ctx, req, sub, as, nil, "")
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
			if signature == "2tPHv7kbUeHRWHgVKKddQqXnjDhuX84kTyCvRy1BmCM4m4Fkq4vJmNAz8A7fXqckrSNRTAKuPmAPWnzr5T7eCChb" {
				msg = common.DecodeHexOrPanic("0300050bcdc56c8d087a301b21144b2ab5e1286b50a5d941ee02f62488db0308b943d2d6c4db1d1f598d6a8197daf51b68d7fc0ef139c4dec5a496bac9679563bd3127dbfb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b63dca1663046f4756ce46e2bc880f3e5f4075486ab71a22da53763d9511e53b3a387fbde731a6a95e59ce4357a2a9d4e93e0dcf6adfa3de29a5d6a18b0943ca2e5a310642242cffec0d9fc9ade1271f1ca01980d7c494a8462df13fa17780e6806a7d517192c568ee08a845f73d29788cf035c3145b21ab344d8062ea9400000000000000000000000000000000000000000000000000000000000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a906a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a000000008c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f859756984b89aebd6266f0b276b84a367bb40327e1d21134fa569bc5f51d1e9ad810607030306000404000000070200013400000000604d160000000000520000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9080101431408fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b0100000000000000000000000000000000000000000000000000000000000000000a0700040501070809000803010402090740420f0000000000070202050c02000000404b4c0000000000")
			}
			if signature == "5s3UBMymdgDHwYvuaRdq9SLq94wj5xAgYEsDDB7TQwwuLy1TTYcSf6rF4f2fDfF7PnA9U75run6r1pKm9K1nusCR" {
				msg = common.DecodeHexOrPanic("02010308cdc56c8d087a301b21144b2ab5e1286b50a5d941ee02f62488db0308b943d2d619e5c93ee8fb3f54284c769278771b90851ef9db78db616e0e7ad0f9a8ab8969bad4af79952644bd80881b3934b3e278ad2f4eeea3614e1c428350d905eac4eca3224f33a7dc3529a89d8666b56615eeaca95e34aedbf364f9145cb424e84525c4db1d1f598d6a8197daf51b68d7fc0ef139c4dec5a496bac9679563bd3127db06a7d517192c568ee08a845f73d29788cf035c3145b21ab344d8062ea9400000000000000000000000000000000000000000000000000000000000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9c35f67d9654b08f6cb7dd06de4319d70c58903b0687b110b0a13e2d453300b9e020603020500040400000007030304010a0f40420f000000000008")
			}
		}
		call, err := node.store.ReadSystemCallByMessage(ctx, hex.EncodeToString(msg))
		if err != nil || call == nil {
			panic(fmt.Errorf("store.ReadSystemCallByMessage(%x) => %v %v", msg, call, err))
		}
		if call.State != common.RequestStatePending {
			return node.failRequest(ctx, req, "")
		}

		var txs []*mtg.Transaction
		var compaction string
		if call.Type == store.CallTypePostProcess {
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
				asset, err := common.SafeReadAssetUntilSufficient(ctx, node.mixin, da.AssetId)
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

		err = node.store.ConfirmSystemCallSuccessWithRequest(ctx, req, call, txs, compaction)
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
		err = node.store.ConfirmSystemCallFailWithRequest(ctx, req, call)
		if err != nil {
			panic(err)
		}
		return nil, ""
	default:
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

func (node *Node) processSignerPrepare(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleSigner {
		panic(req.Role)
	}
	if req.Action != OperationTypeSignPrepare {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	session := uuid.Must(uuid.FromBytes(extra[:16])).String()
	extra = extra[16:]
	if !bytes.Equal(extra, PrepareExtra) {
		logger.Printf("invalid prepare extra: %s", string(extra))
		return node.failRequest(ctx, req, "")
	}

	s, err := node.store.ReadSession(ctx, session)
	if err != nil || s == nil {
		panic(fmt.Errorf("store.ReadSession(%s) => %v", session, err))
	}
	if s.PreparedAt.Valid {
		logger.Printf("session %s is prepared", s.Id)
		return node.failRequest(ctx, req, "")
	}

	err = node.store.PrepareSessionSignerIfNotExist(ctx, s.Id, req.Output.Senders[0], req.Output.SequencerCreatedAt)
	logger.Printf("store.PrepareSessionSignerIfNotExist(%s %s %s) => %v", s.Id, node.id, req.Output.Senders[0], err)
	if err != nil {
		panic(fmt.Errorf("store.PrepareSessionSignerIfNotExist(%v) => %v", s, err))
	}
	signers, err := node.store.ListSessionSignerResults(ctx, s.Id)
	logger.Printf("store.ListSessionSignerResults(%s) => %d %v", s.Id, len(signers), err)
	if err != nil {
		panic(fmt.Errorf("store.ListSessionSignerResults(%s) => %v", s.Id, err))
	}
	if len(signers) <= node.threshold {
		logger.Printf("insufficient prepared signers: %d %d", len(signers), node.threshold)
		return node.failRequest(ctx, req, "")
	}
	err = node.store.MarkSessionPreparedWithRequest(ctx, req, s.Id, req.Output.SequencerCreatedAt)
	if err != nil {
		panic(fmt.Errorf("node.MarkSessionPreparedWithRequest(%s %v) => %v", s.Id, req.Output.SequencerCreatedAt, err))
	}
	return nil, ""
}

func (node *Node) processSignerSignatureResponse(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	logger.Printf("node.processSignerSignatureResponse(%s)", string(node.id))
	if req.Role != RequestRoleSigner {
		panic(req.Role)
	}
	if req.Action != OperationTypeSignOutput {
		panic(req.Action)
	}
	extra := req.ExtraBytes()
	sid := uuid.FromBytesOrNil(extra[:16]).String()
	signature := extra[16:]
	s, err := node.store.ReadSession(ctx, sid)
	if err != nil || s == nil {
		panic(fmt.Errorf("store.ReadSession(%s) => %v %v", sid, s, err))
	}
	call, err := node.store.ReadSystemCallByRequestId(ctx, s.RequestId, common.RequestStatePending)
	if err != nil || call == nil {
		panic(fmt.Errorf("store.ReadSystemCallByRequestId(%s) => %v %v", s.RequestId, call, err))
	}
	if call.State == common.RequestStateDone || call.Signature.Valid {
		logger.Printf("invalid call %s: %d %s", call.RequestId, call.State, call.Signature.String)
		return node.failRequest(ctx, req, "")
	}

	self := len(req.Output.Senders) == 1 && req.Output.Senders[0] == string(node.id)
	err = node.store.UpdateSessionSigner(ctx, s.Id, req.Output.Senders[0], signature, req.Output.SequencerCreatedAt, self)
	if err != nil {
		panic(fmt.Errorf("store.UpdateSessionSigner(%s %s) => %v", s.Id, req.Output.Senders[0], err))
	}
	signers, err := node.store.ListSessionSignerResults(ctx, s.Id)
	logger.Printf("store.ListSessionSignerResults(%s) => %d", s.Id, len(signers))
	if err != nil {
		panic(fmt.Errorf("store.ListSessionSignerResults(%s) => %d %v", s.Id, len(signers), err))
	}
	finished, sig := node.verifySessionSignerResults(ctx, s, signers)
	logger.Printf("node.verifySessionSignerResults(%v, %d) => %t %x", s, len(signers), finished, sig)
	if !finished {
		return node.failRequest(ctx, req, "")
	}
	if l := len(signers); l <= node.threshold {
		panic(s.Id)
	}
	extra = common.DecodeHexOrPanic(s.Extra)
	if s.State == common.RequestStateInitial && s.PreparedAt.Valid {
		// this could happend only after crash or not commited
		err = node.store.MarkSessionPending(ctx, s.Id, s.Public, extra)
		logger.Printf("store.MarkSessionPending(%v, processSignerResult) => %x %v\n", s, extra, err)
		if err != nil {
			panic(err)
		}
	}
	_, share, path, err := node.readKeyByFingerPath(ctx, s.Public)
	logger.Printf("node.readKeyByFingerPath(%s) => %v", s.Public, err)
	if err != nil {
		panic(err)
	}
	valid, vsig := node.verifySessionSignature(common.DecodeHexOrPanic(call.Message), sig, share, path)
	logger.Printf("node.verifySessionSignature(%v, %x) => %t", s, sig, valid)
	if !valid || !bytes.Equal(sig, vsig) {
		panic(hex.EncodeToString(vsig))
	}

	if common.CheckTestEnvironment(ctx) {
		key := "SIGNER:" + sid
		val, err := node.store.ReadProperty(ctx, key)
		if err != nil {
			panic(err)
		}
		if val == "" {
			extra := []byte{OperationTypeSignOutput}
			extra = append(extra, signature...)
			err = node.store.WriteProperty(ctx, key, hex.EncodeToString(extra))
			if err != nil {
				panic(err)
			}
		}
	}
	err = node.store.AttachSystemCallSignatureWithRequest(ctx, req, call, s.Id, base64.StdEncoding.EncodeToString(sig))
	if err != nil {
		panic(fmt.Errorf("store.AttachSystemCallSignatureWithRequest(%s %v) => %v", s.Id, call, err))
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

	err = node.store.WriteSubCallAndAssetsWithRequest(ctx, req, new, nil, nil, "")
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
	ts := solanaApp.ExtractTransfersFromTransaction(ctx, tx, rpcTx.Meta)

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

type ReferencedTxAsset struct {
	Solana bool
	Amount decimal.Decimal
	Asset  *bot.AssetNetwork
}

func (node *Node) getSystemCallRelatedAsset(ctx context.Context, requestId string) []*ReferencedTxAsset {
	req, err := node.store.ReadRequest(ctx, requestId)
	if err != nil || req == nil {
		panic(fmt.Errorf("store.ReadRequest(%s) => %v %v", requestId, req, err))
	}
	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, req.MixinHash.String())
	if err != nil || ver == nil {
		panic(fmt.Errorf("group.ReadKernelTransactionUntilSufficient(%s) => %v %v", req.MixinHash.String(), ver, err))
	}
	if common.CheckTestEnvironment(ctx) {
		h1, _ := crypto.HashFromString("a8eed784060b200ea7f417309b12a33ced8344c24f5cdbe0237b7fc06125f459")
		h2, _ := crypto.HashFromString("01c43005fd06e0b8f06a0af04faf7530331603e352a11032afd0fd9dbd84e8ee")
		ver.References = []crypto.Hash{h1, h2}
	}

	var as []*ReferencedTxAsset
	for _, ref := range ver.References {
		refVer, err := node.group.ReadKernelTransactionUntilSufficient(ctx, ref.String())
		if err != nil {
			panic(fmt.Errorf("group.ReadKernelTransactionUntilSufficient(%s) => %v %v", ref.String(), refVer, err))
		}
		if refVer == nil {
			continue
		}

		outputs := node.group.ListOutputsByTransactionHash(ctx, ref.String(), req.Sequence)
		if len(outputs) == 0 {
			continue
		}
		total := decimal.NewFromInt(0)
		for _, output := range outputs {
			total = total.Add(output.Amount)
		}

		asset, err := common.SafeReadAssetUntilSufficient(ctx, node.mixin, outputs[0].AssetId)
		if err != nil {
			panic(err)
		}
		as = append(as, &ReferencedTxAsset{
			Solana: asset.ChainID == solanaApp.SolanaChainBase,
			Amount: total,
			Asset:  asset,
		})
	}
	return as
}
