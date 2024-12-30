package computer

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	mc "github.com/MixinNetwork/mixin/common"
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
// only create mtg withdrawals txs and main system call here
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

	call := &store.SystemCall{
		RequestId:       req.Id,
		Superior:        req.Id,
		Type:            store.CallTypeMain,
		NonceAccount:    user.NonceAccount,
		Public:          user.Public,
		Message:         tx.Message.ToBase64(),
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
	if err != nil || ver == nil {
		panic(err)
	}
	for _, ref := range ver.References {
		refVer, err := node.group.ReadKernelTransactionUntilSufficient(ctx, ref.String())
		if err != nil {
			panic(err)
		}
		if refVer == nil {
			continue
		}

		outputs := node.group.ListOutputsByTransactionHash(ctx, ver.PayloadHash().String(), req.Sequence)
		if len(outputs) == 0 {
			continue
		}
		total := decimal.NewFromInt(0)
		for _, output := range outputs {
			total = total.Add(output.Amount)
		}

		asset, err := node.mixin.SafeReadAsset(ctx, outputs[0].AssetId)
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

	extra := req.ExtraBytes()
	if len(extra) != 64 {
		return node.failRequest(ctx, req, "")
	}
	publicKey := extra[:32]
	nonceAccount := solana.PublicKeyFromBytes(extra[32:])

	public := hex.EncodeToString(publicKey)
	old, _, err := node.store.ReadKeyByFingerprint(ctx, hex.EncodeToString(common.Fingerprint(public)))
	logger.Printf("store.ReadKeyByFingerprint(%s) => %s %v", public, old, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadKeyByFingerprint() => %v", err))
	} else if old == "" {
		return node.failRequest(ctx, req, "")
	}
	key, err := node.store.ReadFirstGeneratedKey(ctx, OperationTypeKeygenInput)
	logger.Printf("store.ReadFirstGeneratedKey() => %s %v", key, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadFirstGeneratedKey() => %v", err))
	} else if key == "" || old != key {
		return node.failRequest(ctx, req, "")
	}

	oldAccount, err := node.store.ReadNonceAccount(ctx, nonceAccount.String())
	logger.Printf("store.ReadNonceAccount(%s) => %v %v", nonceAccount.String(), oldAccount, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadKeyByFingerprint() => %v", err))
	} else if oldAccount == nil || oldAccount.UserId.Valid {
		return node.failRequest(ctx, req, "")
	}
	account, err := node.store.ReadSpareNonceAccount(ctx)
	logger.Printf("store.ReadFirstGeneratedNonceAccount() => %v %v", account, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadFirstGeneratedNonceAccount() => %v", err))
	} else if account == nil || oldAccount.Address != account.Address {
		return node.failRequest(ctx, req, "")
	}

	err = node.store.WriteSignerUserWithRequest(ctx, req, node.conf.SolanaDepositEntry, key, nonceAccount.String())
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
	signature := string(extra[32:])

	tx, err := node.solanaClient().RPCGetTransaction(ctx, signature)
	if err != nil || tx == nil {
		node.failRequest(ctx, req, "")
	}

	call, err := node.store.ReadSystemCallByRequestId(ctx, reqId, common.RequestStateInitial)
	logger.Printf("store.ReadSystemCallByRequestId(%s) => %v %v", reqId, call, err)
	if err != nil {
		panic(err)
	}
	if call == nil || call.WithdrawedAt.Valid || !slices.Contains(call.GetWithdrawalIds(), txId) {
		return node.failRequest(ctx, req, "")
	}

	err = node.store.MarkSystemCallWithdrawedWithRequest(ctx, req, call, txId)
	if err != nil {
		panic(err)
	}
	return nil, ""
}

func (node *Node) processConfirmCall(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeCreateNonce {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	flag, extra := extra[0], extra[1:]
	// TODO check tx confirmed

	switch flag {
	case ConfirmFlagMixinWithdrawal:
		txId := uuid.Must(uuid.FromBytes(extra[:16])).String()
		outputId := uuid.Must(uuid.FromBytes(extra[16:])).String()
		call, err := node.store.ReadSystemCallByRequestId(ctx, outputId, common.RequestStateInitial)
		logger.Printf("store.ReadSystemCallByRequestId(%s) => %v %v", outputId, call, err)
		if err != nil {
			panic(err)
		}
		if call == nil || call.WithdrawedAt.Valid || !slices.Contains(call.GetWithdrawalIds(), txId) {
			return node.failRequest(ctx, req, "")
		}

		err = node.store.MarkSystemCallWithdrawedWithRequest(ctx, req, call, txId)
		if err != nil {
			panic(err)
		}
		return nil, ""
	case ConfirmFlagOnChainTx:
		hash := base58.Encode(extra)
		_ = solana.MustSignatureFromBase58(hash)
		transaction, err := node.solanaClient().RPCGetTransaction(ctx, hash)
		if err != nil {
			panic(err)
		}
		tx, err := transaction.Transaction.GetTransaction()
		if err != nil {
			panic(err)
		}
		call, err := node.store.ReadSystemCallByMessage(ctx, tx.Message.ToBase64())
		if err != nil || call == nil {
			panic(err)
		}
		if call.State != common.RequestStatePending {
			return node.failRequest(ctx, req, "")
		}
		err = node.store.ConfirmSystemCallWithRequest(ctx, req, call.RequestId)
		if err != nil {
			panic(err)
		}
		return nil, ""
	default:
		return node.failRequest(ctx, req, "")
	}
}

func (node *Node) processSignerPrepare(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleSigner {
		panic(req.Role)
	}
	if req.Action != OperationTypeSignInput {
		panic(req.Action)
	}

	extra := string(req.ExtraBytes())
	items := strings.Split(extra, ",")
	if len(items) != 2 || items[0] != PrepareExtra {
		return node.failRequest(ctx, req, "")
	}

	s, err := node.store.ReadSession(ctx, items[1])
	if err != nil {
		panic(fmt.Errorf("store.ReadSession(%s) => %v", items[1], err))
	} else if s.PreparedAt.Valid {
		return node.failRequest(ctx, req, "")
	}
	signers, err := node.store.ListSessionSignerResults(ctx, s.Id)
	if err != nil {
		panic(fmt.Errorf("store.ListSessionSignerResults(%s) => %d %v", s.Id, len(signers), err))
	}

	sufficient := len(signers)+1 > node.threshold
	err = node.store.PrepareSessionSignerWithRequest(ctx, req, sufficient, s.Id, req.Output.Senders[0], req.Output.SequencerCreatedAt)
	if err != nil {
		panic(fmt.Errorf("node.PrepareSessionSignerWithRequest(%t %s %s %s) => %v", sufficient, s.Id, req.Output.Senders[0], req.Output.SequencerCreatedAt, err))
	}

	return nil, ""
}

func (node *Node) processSignerSignatureResponse(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
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
	call, err := node.store.ReadSystemCallByMessage(ctx, s.Extra)
	if err != nil || call == nil {
		panic(fmt.Errorf("store.ReadSystemCallByMessage(%s) => %v %v", s.Extra, call, err))
	}
	if call.Signature.Valid {
		return node.failRequest(ctx, req, "")
	}

	// TODO verify signature

	err = node.store.AttachSystemCallSignatureWithRequest(ctx, req, call, s.Id, base64.StdEncoding.EncodeToString(signature))
	if err != nil {
		panic(fmt.Errorf("store.AttachSystemCallSignatureWithRequest(%s %v) => %v", s.Id, call, err))
	}

	return nil, ""
}
