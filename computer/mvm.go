package computer

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
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
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	SignerKeygenMaximum = 128

	ConfirmFlagMixinWithdrawal = 0
	ConfirmFlagOnChainTx       = 1
)

func (node *Node) processAddUser(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleUser {
		panic(req.Role)
	}

	mix := string(req.ExtraBytes())
	_, err := mc.NewAddressFromString(mix)
	logger.Printf("common.NewAddressFromString(%s) => %v", mix, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}

	old, err := node.store.ReadUserByAddress(ctx, mix)
	logger.Printf("store.ReadUserByAddress(%s) => %v %v", mix, old, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadUserByAddress(%s) => %v", mix, err))
	} else if old != nil {
		return node.failRequest(ctx, req, "")
	}

	count, err := node.store.CountSpareKeys(ctx)
	logger.Printf("store.CountSpareKeys(%v) => %d %v", req, count, err)
	if err != nil {
		panic(fmt.Errorf("store.CountSpareKeys() => %v", err))
	} else if count == 0 {
		return node.failRequest(ctx, req, "")
	}
	count, err = node.store.CountSpareNonceAccounts(ctx)
	logger.Printf("store.CountSpareNonceAccounts(%v) => %d %v", req, count, err)
	if err != nil {
		panic(fmt.Errorf("store.CountSpareNonceAccounts() => %v", err))
	} else if count == 0 {
		return node.failRequest(ctx, req, "")
	}

	err = node.store.WriteUserWithRequest(ctx, req, mix)
	if err != nil {
		panic(fmt.Errorf("store.WriteUserWithRequest(%v %s) => %v", req, mix, err))
	}
	return nil, ""
}

// To finish a system call may take up to 4 steps:
// 1 withdrawal
// 2 transfer
// 3 call
// 4 postprocess
// only create mtg withdrawals txs and main system call by group
// other calls should be created by observer
func (node *Node) processSystemCall(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleUser {
		panic(req.Role)
	}
	if req.AssetId != mtg.StorageAssetId {
		return node.failRequest(ctx, req, "")
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
	userAccount := solanaApp.PublicKeyFromEd25519Public(user.Public)

	tx, err := solana.TransactionFromBytes(data[8:])
	logger.Printf("solana.TransactionFromBytes(%x) => %v %v", data[8:], tx, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	hasUser := tx.IsSigner(userAccount)
	hasKey := tx.IsSigner(node.solanaAccount())
	if !hasKey || !hasUser {
		logger.Printf("tx.IsSigner(user) => %t", hasUser)
		logger.Printf("tx.IsSigner(mtg) => %t", hasKey)
		return node.failRequest(ctx, req, "")
	}

	ins := tx.Message.Instructions[0]
	accounts, err := ins.ResolveInstructionAccounts(&tx.Message)
	if err != nil {
		panic(err)
	}
	advance, flag := solanaApp.DecodeNonceAdvance(accounts, ins.Data)
	logger.Printf("solana.DecodeNonceAdvance() => %v %t", advance.GetNonceAccount().PublicKey, flag)
	if !flag || advance.GetNonceAccount().PublicKey.String() != user.NonceAccount {
		return node.failRequest(ctx, req, "")
	}

	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		panic(err)
	}
	call := &store.SystemCall{
		RequestId:       req.Id,
		Superior:        req.Id,
		Type:            store.CallTypeMain,
		NonceAccount:    user.NonceAccount,
		Public:          user.Public,
		Message:         hex.EncodeToString(msg),
		Raw:             tx.MustToBase64(),
		State:           common.RequestStateInitial,
		WithdrawalIds:   "",
		WithdrawedAt:    sql.NullTime{Valid: true, Time: req.CreatedAt},
		Signature:       sql.NullString{Valid: false},
		RequestSignerAt: sql.NullTime{Valid: false},
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}

	var txs []*mtg.Transaction
	var compaction string
	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, req.MixinHash.String())
	logger.Printf("group.ReadKernelTransactionUntilSufficient(%s) => %v %v", req.MixinHash.String(), ver, err)
	if err != nil || ver == nil {
		panic(err)
	}
	if common.CheckTestEnvironment(ctx) {
		h1, _ := crypto.HashFromString("a8eed784060b200ea7f417309b12a33ced8344c24f5cdbe0237b7fc06125f459")
		h2, _ := crypto.HashFromString("01c43005fd06e0b8f06a0af04faf7530331603e352a11032afd0fd9dbd84e8ee")
		ver.References = []crypto.Hash{h1, h2}
	}
	for _, ref := range ver.References {
		refVer, err := node.group.ReadKernelTransactionUntilSufficient(ctx, ref.String())
		logger.Printf("group.ReadKernelTransactionUntilSufficient(%s) => %v %v", ref.String(), refVer, err)
		if err != nil {
			panic(err)
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

		asset, err := bot.ReadAsset(ctx, outputs[0].AssetId)
		if err != nil {
			panic(err)
		}
		if asset.ChainID != common.SafeSolanaChainId {
			continue
		}
		id := common.UniqueId(req.Id, asset.AssetID)
		id = common.UniqueId(id, "withdrawal")
		memo := []byte(req.Id)
		tx := node.buildWithdrawalTransaction(ctx, req.Output, asset.AssetID, total.String(), memo, userAccount.String(), "", id)
		if tx == nil {
			return node.failRequest(ctx, req, asset.AssetID)
		}
		txs = append(txs, tx)
	}
	if len(txs) > 0 {
		ids := []string{}
		for _, tx := range txs {
			ids = append(ids, tx.TraceId)
		}
		call.WithdrawalIds = strings.Join(ids, ",")
		call.WithdrawedAt = sql.NullTime{Valid: false}
	}

	err = node.store.WriteInitialSystemCallWithRequest(ctx, req, call, txs, compaction)
	logger.Printf("solana.WriteInitialSystemCallWithRequest(%v %d %s) => %v", call, len(txs), compaction, err)
	if err != nil {
		panic(err)
	}

	return txs, ""
}

func (node *Node) processSignerKeygenRequests(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeKeygenInput {
		panic(req.Action)
	}

	batch, ok := new(big.Int).SetString(req.ExtraHEX, 16)
	if !ok || batch.Cmp(big.NewInt(1)) < 0 || batch.Cmp(big.NewInt(SignerKeygenMaximum)) > 0 {
		return node.failRequest(ctx, req, "")
	}

	var sessions []*store.Session
	members := node.GetMembers()
	threshold := node.conf.MTG.Genesis.Threshold
	for i := 0; i < int(batch.Int64()); i++ {
		now := time.Now().UTC()
		id := common.UniqueId(req.Id, fmt.Sprintf("%8d", i))
		id = common.UniqueId(id, fmt.Sprintf("MTG:%v:%d", members, threshold))
		sessions = append(sessions, &store.Session{
			Id:         id,
			RequestId:  req.Id,
			MixinHash:  req.MixinHash.String(),
			MixinIndex: req.Output.OutputIndex,
			Index:      i,
			Operation:  OperationTypeKeygenInput,
			CreatedAt:  now,
		})
	}

	err := node.store.WriteSessionsWithRequest(ctx, req, sessions, false)
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
	if err != nil || s == nil {
		panic(fmt.Errorf("store.ReadSession(%s) => %v %v", sid, s, err))
	}
	key, _, err := node.store.ReadKeyByFingerprint(ctx, hex.EncodeToString(common.Fingerprint(hex.EncodeToString(public))))
	if err != nil || key != hex.EncodeToString(public) {
		panic(fmt.Errorf("store.readKeyByFingerPath(%x) => %s %v", public, key, err))
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

	err = node.store.MarkKeyComfirmedWithRequest(ctx, req, hex.EncodeToString(public))
	if err != nil {
		panic(fmt.Errorf("store.WriteSessionsWithRequest(%v) => %v", req, err))
	}
	return nil, ""
}

func (node *Node) processSignerKeyInitRequests(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeInitMPCKey {
		panic(req.Action)
	}
	initialized, err := node.store.CheckMpcKeyInitialized(ctx)
	logger.Printf("store.CheckMpcKeyInitialized() => %t %v", initialized, err)
	if err != nil {
		panic(fmt.Errorf("store.CheckMpcKeyInitialized() => %v", err))
	} else if initialized {
		return node.failRequest(ctx, req, "")
	}

	publicKey := req.ExtraBytes()
	if len(publicKey) != 32 {
		return node.failRequest(ctx, req, "")
	}

	public := hex.EncodeToString(publicKey)
	old, _, err := node.store.ReadKeyByFingerprint(ctx, hex.EncodeToString(common.Fingerprint(public)))
	logger.Printf("store.ReadKeyByFingerprint(%s) => %s %v", public, old, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadKeyByFingerprint() => %v", err))
	} else if old == "" {
		return node.failRequest(ctx, req, "")
	}
	key, err := node.store.ReadFirstGeneratedKey(ctx)
	logger.Printf("store.ReadFirstGeneratedKey() => %s %v", key, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadFirstGeneratedKey() => %v", err))
	} else if key == "" || old != key {
		return node.failRequest(ctx, req, "")
	}

	err = node.store.WriteSignerUserWithRequest(ctx, req, node.conf.SolanaDepositEntry, key)
	if err != nil {
		panic(fmt.Errorf("store.WriteSignerUserWithRequest(%v) => %v", req, err))
	}
	return nil, ""
}

func (node *Node) processCreateOrUpdateNonceAccount(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeCreateNonce {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	if len(extra) != 64 {
		return node.failRequest(ctx, req, "")
	}
	address := solana.PublicKeyFromBytes(extra[0:32]).String()
	hash := solana.HashFromBytes(extra[32:]).String()

	old, err := node.store.ReadNonceAccount(ctx, address)
	if err != nil {
		panic(fmt.Errorf("store.ReadNonceAccount(%s) => %v", address, err))
	} else if old != nil && old.Hash == hash {
		return node.failRequest(ctx, req, "")
	}

	err = node.store.WriteOrUpdateNonceAccount(ctx, req, address, hash)
	if err != nil {
		panic(fmt.Errorf("store.WriteOrUpdateNonceAccount(%v %s %s) => %v", req, address, hash, err))
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

	withdrawalHash, err := common.SafeReadWithdrawalHashUntilSufficient(ctx, node.safeUser(), txId)
	logger.Printf("common.SafeReadWithdrawalHashUntilSufficient(%s) => %s %v", txId, withdrawalHash, err)
	if err != nil {
		panic(err)
	}
	tx, err := node.solanaClient().RPCGetTransaction(ctx, withdrawalHash)
	logger.Printf("solana.RPCGetTransaction(%s) => %v %v", withdrawalHash, tx, err)
	if err != nil {
		panic(err)
	}
	if tx == nil {
		return node.failRequest(ctx, req, "")
	}

	call, err := node.store.ReadSystemCallByRequestId(ctx, reqId, common.RequestStateInitial)
	logger.Printf("store.ReadSystemCallByRequestId(%s) => %v %v", reqId, call, err)
	if err != nil {
		panic(err)
	}
	if call == nil || call.WithdrawedAt.Valid || !slices.Contains(call.GetWithdrawalIds(), txId) {
		return node.failRequest(ctx, req, "")
	}
	ids := []string{}
	for _, id := range call.GetWithdrawalIds() {
		if id == txId {
			continue
		}
		ids = append(ids, id)
	}
	call.WithdrawalIds = strings.Join(ids, ",")
	if len(ids) == 0 {
		call.WithdrawedAt = sql.NullTime{Valid: true, Time: req.CreatedAt}
		_, as := node.mintExternalTokens(ctx, call, nil)
		if len(as) == 0 {
			call.State = common.RequestStatePending
		}
	}

	err = node.store.MarkSystemCallWithdrawedWithRequest(ctx, req, call, txId, withdrawalHash)
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
	nonceAccount := solana.PublicKeyFromBytes(extra[16:48]).String()
	hash, err := crypto.HashFromString(hex.EncodeToString(extra[48:80]))
	if err != nil {
		panic(err)
	}
	extra = extra[80:]
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
	nonce, err := node.store.ReadNonceAccount(ctx, nonceAccount)
	logger.Printf("store.ReadNonceAccount(%s) => %v %v", nonceAccount, nonce, err)
	if err != nil {
		panic(nonceAccount)
	}
	if nonce == nil || nonce.CallId.Valid || nonce.UserId.Valid {
		return node.failRequest(ctx, req, "")
	}
	raw := node.readStorageExtraFromObserver(ctx, hash)
	tx, err := solana.TransactionFromBytes(raw)
	logger.Printf("solana.TransactionFromBytes(%x) => %v %v", raw, tx, err)
	if err != nil {
		panic(err)
	}

	err = node.VerifySubSystemCall(ctx, tx, solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry), solanaApp.PublicKeyFromEd25519Public(call.Public), solana.MustPublicKeyFromBase58(nonceAccount))
	logger.Printf("node.VerifySubSystemCall(%s %s) => %v", node.conf.SolanaDepositEntry, call.Public, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}

	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		panic(err)
	}
	new := &store.SystemCall{
		RequestId:       req.Id,
		Superior:        call.RequestId,
		NonceAccount:    nonceAccount,
		Message:         hex.EncodeToString(msg),
		Raw:             tx.MustToBase64(),
		State:           common.RequestStatePending,
		WithdrawalIds:   "",
		WithdrawedAt:    sql.NullTime{Valid: true, Time: req.CreatedAt},
		Signature:       sql.NullString{Valid: false},
		RequestSignerAt: sql.NullTime{Valid: false},
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}
	switch call.State {
	case common.RequestStateInitial:
		if nonce.UserId.Valid || nonce.CallId.Valid {
			return node.failRequest(ctx, req, "")
		}
		mtgUser, err := node.store.ReadUser(ctx, store.MPCUserId)
		if err != nil {
			panic(err)
		}
		new.Public = mtgUser.Public
		new.Type = store.CallTypePrepare
	case common.RequestStateDone:
		new.Public = call.Public
		new.Type = store.CallTypePostProcess
	default:
		panic(req)
	}

	err = node.store.WriteSubCallAndAssetsWithRequest(ctx, req, new, as, nil, "")
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
	signature := base58.Encode(extra[:64])
	_ = solana.MustSignatureFromBase58(signature)
	updatedHash := solana.PublicKeyFromBytes(extra[64:]).String()

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
	call, err := node.store.ReadSystemCallByMessage(ctx, hex.EncodeToString(msg))
	if err != nil || call == nil {
		panic(err)
	}
	if call.State != common.RequestStatePending {
		return node.failRequest(ctx, req, "")
	}
	nonce, err := node.store.ReadNonceAccount(ctx, call.NonceAccount)
	if err != nil || nonce == nil {
		panic(err)
	}
	if nonce.Hash == updatedHash {
		return node.failRequest(ctx, req, "")
	}
	nonce.Hash = updatedHash

	err = node.store.ConfirmSystemCallWithRequest(ctx, req, call, nonce)
	if err != nil {
		panic(err)
	}
	return nil, ""
}

func (node *Node) processObserverRequestSession(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
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
		Public:     hex.EncodeToString(common.Fingerprint(call.Public)),
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
	if err != nil {
		panic(fmt.Errorf("store.PrepareSessionSignerIfNotExist(%v) => %v", s, err))
	}
	signers, err := node.store.ListSessionSignerResults(ctx, s.Id)
	if err != nil {
		panic(fmt.Errorf("store.ListSessionSignerResults(%s) => %d %v", s.Id, len(signers), err))
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
	logger.Printf("store.ListSessionSignerResults(%s) => %d %x", s.Id, len(signers), s.Id)
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
	holder, _, _, err := node.readKeyByFingerPath(ctx, s.Public)
	logger.Printf("node.readKeyByFingerPath(%s) => %s %v", s.Public, holder, err)
	if err != nil {
		panic(err)
	}
	valid, vsig := node.verifySessionSignature(holder, common.DecodeHexOrPanic(call.Message), sig)
	logger.Printf("node.verifySessionSignature(%v, %s, %x) => %t", s, holder, extra, valid)
	if !valid || !bytes.Equal(sig, vsig) {
		panic(hex.EncodeToString(vsig))
	}

	err = node.store.AttachSystemCallSignatureWithRequest(ctx, req, call, s.Id, base64.StdEncoding.EncodeToString(sig))
	if err != nil {
		panic(fmt.Errorf("store.AttachSystemCallSignatureWithRequest(%s %v) => %v", s.Id, call, err))
	}

	return nil, ""
}

func (node *Node) processSignerCreateDepositCall(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	logger.Printf("node.processSignerCreateDepositCall(%s)", string(node.id))
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeDeposit {
		panic(req.Action)
	}
	extra := req.ExtraBytes()
	user := solana.PublicKeyFromBytes(extra[:32])
	nonceAccount := solana.PublicKeyFromBytes(extra[32:64]).String()
	hash, err := crypto.HashFromString(hex.EncodeToString(extra[64:96]))

	nonce, err := node.store.ReadNonceAccount(ctx, nonceAccount)
	logger.Printf("store.ReadNonceAccount(%s) => %v %v", nonceAccount, nonce, err)
	if err != nil {
		panic(nonceAccount)
	}
	if nonce == nil || nonce.CallId.Valid || nonce.UserId.Valid {
		return node.failRequest(ctx, req, "")
	}

	raw := node.readStorageExtraFromObserver(ctx, hash)
	tx, err := solana.TransactionFromBytes(raw)
	logger.Printf("solana.TransactionFromBytes(%x) => %v %v", raw, tx, err)
	if err != nil {
		panic(err)
	}

	err = node.VerifySubSystemCall(ctx, tx, solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry), user, solana.MustPublicKeyFromBase58(nonceAccount))
	logger.Printf("node.VerifySubSystemCall(%s %s) => %v", node.conf.SolanaDepositEntry, user.String(), err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}

	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		panic(err)
	}
	new := &store.SystemCall{
		RequestId:       req.Id,
		Superior:        req.Id,
		Type:            store.CallTypeMain,
		Public:          hex.EncodeToString(user.Bytes()),
		NonceAccount:    nonceAccount,
		Message:         hex.EncodeToString(msg),
		Raw:             tx.MustToBase64(),
		State:           common.RequestStatePending,
		WithdrawalIds:   "",
		WithdrawedAt:    sql.NullTime{Valid: true, Time: req.CreatedAt},
		Signature:       sql.NullString{Valid: false},
		RequestSignerAt: sql.NullTime{Valid: false},
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
	}

	err = node.store.WriteSubCallAndAssetsWithRequest(ctx, req, new, nil, nil, "")
	if err != nil {
		panic(err)
	}

	return nil, ""
}

func (node *Node) mintExternalTokens(ctx context.Context, call *store.SystemCall, nonce *store.NonceAccount) (*solana.Transaction, []*store.DeployedAsset) {
	user, err := node.store.ReadUserByPublic(ctx, call.Public)
	if err != nil {
		panic(err)
	}
	mtgUser, err := node.store.ReadUser(ctx, store.MPCUserId)
	if err != nil {
		panic(err)
	}
	req, err := node.store.ReadRequest(ctx, call.RequestId)
	if err != nil {
		panic(err)
	}
	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, req.MixinHash.String())
	if err != nil || ver == nil {
		panic(err)
	}
	if common.CheckTestEnvironment(ctx) {
		h1, _ := crypto.HashFromString("a8eed784060b200ea7f417309b12a33ced8344c24f5cdbe0237b7fc06125f459")
		h2, _ := crypto.HashFromString("01c43005fd06e0b8f06a0af04faf7530331603e352a11032afd0fd9dbd84e8ee")
		ver.References = []crypto.Hash{h1, h2}
	}

	destination := solanaApp.PublicKeyFromEd25519Public(user.Public)
	var transfers []solanaApp.TokenTransfers
	var as []*store.DeployedAsset
	for _, ref := range ver.References {
		refVer, err := node.group.ReadKernelTransactionUntilSufficient(ctx, ref.String())
		if err != nil {
			panic(err)
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

		asset, err := bot.ReadAsset(ctx, outputs[0].AssetId)
		if err != nil {
			panic(err)
		}
		if asset.ChainID == common.SafeSolanaChainId {
			continue
		}
		da, err := node.store.ReadDeployedAsset(ctx, asset.AssetID)
		if err != nil {
			panic(err)
		}
		if da == nil {
			key, err := solana.NewRandomPrivateKey()
			if err != nil {
				panic(err)
			}
			da = &store.DeployedAsset{
				AssetId:    asset.AssetID,
				Address:    key.PublicKey().String(),
				PrivateKey: &key,
			}
			as = append(as, da)
		}

		transfers = append(transfers, solanaApp.TokenTransfers{
			SolanaAsset: false,
			AssetId:     asset.AssetID,
			ChainId:     asset.ChainID,
			Mint:        da.PublicKey(),
			Destination: destination,
			Amount:      total.BigInt().Uint64(),
			Decimals:    uint8(asset.Precision),
		})
	}
	if len(transfers) == 0 || nonce == nil {
		return nil, as
	}

	tx, err := node.solanaClient().MintTokens(ctx, node.solanaAccount(), mtgUser.PublicKey(), nonce.Account(), transfers)
	if err != nil {
		panic(err)
	}
	for _, da := range as {
		if da.PrivateKey == nil {
			continue
		}
		_, err = tx.PartialSign(solanaApp.BuildSignersGetter(*da.PrivateKey))
		if err != nil {
			panic(err)
		}
	}
	return tx, as
}

func (node *Node) transferRestTokens(ctx context.Context, source solana.PublicKey, nonce *store.NonceAccount) *solana.Transaction {
	spls, err := node.solanaClient().RPCGetTokenAccountsByOwner(ctx, source)
	if err != nil {
		panic(err)
	}
	sol, err := node.solanaClient().RPCGetAccount(ctx, source)
	if err != nil {
		panic(err)
	}

	var transfers []solanaApp.TokenTransfers
	if sol.Value.Lamports > 0 {
		transfers = append(transfers, solanaApp.TokenTransfers{
			SolanaAsset: true,
			AssetId:     common.SafeSolanaChainId,
			ChainId:     common.SafeSolanaChainId,
			Destination: solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry),
			Amount:      sol.Value.Lamports,
		})
	}
	for _, token := range spls {
		if token.Amount == 0 {
			continue
		}
		transfer := solanaApp.TokenTransfers{
			Mint:        token.Mint,
			Destination: solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry),
			Amount:      token.Amount,
			Decimals:    9,
		}
		asset, err := node.store.ReadDeployedAssetByAddress(ctx, token.Mint.String())
		if err != nil {
			panic(err)
		}
		transfer.SolanaAsset = asset == nil
		if transfer.SolanaAsset {
			transfer.AssetId = solanaApp.GenerateAssetId(token.Mint.String())
			transfer.ChainId = common.SafeSolanaChainId
		}
		transfers = append(transfers, transfer)
	}
	if len(transfers) == 0 {
		return nil
	}

	tx, err := node.solanaClient().TransferOrBurnTokens(ctx, node.solanaAccount(), source, nonce.Account(), transfers)
	if err != nil {
		panic(err)
	}
	return tx
}
