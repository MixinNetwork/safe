package computer

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
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

// 1 withdrawal
// 2 transfer
// 3 call
// 4 postprocess
func (node *Node) processSystemCall(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleUser {
		panic(req.Role)
	}
	if req.AssetId != mtg.StorageAssetId {
		return node.failRequest(ctx, req, "")
	}
	mtgUser, err := node.store.ReadUser(ctx, store.MPCUserId)
	logger.Printf("store.ReadUser(%s) => %v %v", store.MPCUserId.String(), mtgUser, err)
	if err != nil || mtgUser == nil {
		panic(err)
	}
	nonce, err := node.store.ReadNonceAccount(ctx, mtgUser.NonceAccount)
	logger.Printf("store.ReadNonceAccount(%s) => %v %v", mtgUser.NonceAccount, nonce, err)
	if err != nil || nonce == nil {
		panic(err)
	}
	destination := solanaApp.PublicKeyFromEd25519Public(mtgUser.Public)

	data := req.ExtraBytes()
	x, n := binary.Varint(data[:4])
	logger.Printf("systemCall.Varint(%x) => %d %d", data[:4], x, n)
	if n <= 0 {
		return node.failRequest(ctx, req, "")
	}
	user, err := node.store.ReadUser(ctx, big.NewInt(x))
	logger.Printf("store.ReadUser(%d) => %v %v", x, user, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadUser() => %v", err))
	} else if user == nil {
		return node.failRequest(ctx, req, "")
	}
	var calls []*store.SystemCall

	tx, err := solana.TransactionFromBytes(data[4:])
	logger.Printf("solana.TransactionFromBytes(%x) => %v %v", data[4:], tx, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	now := time.Now().UTC()
	call := store.SystemCall{
		RequestId:       req.Id,
		Superior:        req.Id,
		Type:            store.CallTypeMain,
		Public:          user.Public,
		Message:         tx.Message.ToBase64(),
		Raw:             tx.MustToBase64(),
		State:           common.RequestStateInitial,
		WithdrawalIds:   "",
		WithdrawedAt:    sql.NullTime{Valid: true, Time: now},
		Signature:       sql.NullString{Valid: false},
		RequestSignerAt: sql.NullTime{Valid: false},
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	withdraws := [][2]string{}
	transfers := []solanaApp.TokenTransfers{}
	mintKeys := []solana.PrivateKey{}
	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, req.MixinHash.String())
	if err != nil {
		panic(err)
	}
	for _, ref := range ver.References {
		ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, ref.String())
		if err != nil {
			panic(err)
		}
		if ver == nil {
			continue
		}

		// TODO support in mtg
		outputs := node.group.ListOutputsForTransaction(ctx, ver.PayloadHash().String(), req.Sequence)
		total := decimal.NewFromInt(0)
		for _, output := range outputs {
			if output.State == mtg.SafeUtxoStateUnspent {
				total = total.Add(output.Amount)
			} else {
				panic(req.Id)
			}
		}

		asset, err := node.mixin.SafeReadAsset(ctx, ver.Asset.String())
		if err != nil {
			panic(err)
		}
		if asset.ChainID != common.SafeSolanaChainId {
			deployedAsset, err := node.store.ReadDeployedAsset(ctx, asset.AssetID)
			if err != nil {
				panic(err)
			}
			if deployedAsset == nil {
				key, err := solana.NewRandomPrivateKey()
				if err != nil {
					panic(err)
				}
				mintKeys = append(mintKeys, key)
				deployedAsset = &store.DeployedAsset{
					AssetId: asset.AssetID,
					Address: key.PublicKey().String(),
				}
			}
			transfers = append(transfers, solanaApp.TokenTransfers{
				SolanaAsset: false,
				AssetId:     asset.AssetID,
				ChainId:     asset.ChainID,
				Mint:        deployedAsset.PublicKey(),
				Destination: destination,
				Amount:      total.BigInt().Uint64(),
				Decimals:    uint8(asset.Precision),
			})
			continue
		}

		mint := solana.MustPublicKeyFromBase58(asset.AssetKey)
		transfers = append(transfers, solanaApp.TokenTransfers{
			SolanaAsset: true,
			AssetId:     asset.AssetID,
			ChainId:     asset.ChainID,
			Mint:        mint,
			Destination: destination,
			Amount:      total.BigInt().Uint64(),
			Decimals:    uint8(9),
		})
		withdraws = append(withdraws, [2]string{asset.AssetID, total.String()})
	}

	var txs []*mtg.Transaction
	var compaction string
	if len(withdraws) > 0 {
		// TODO build withdrawal txs with mtg
		if compaction == "" {
			panic(req)
		}
		ids := []string{}
		for _, tx := range txs {
			ids = append(ids, tx.TraceId)
		}
		call.WithdrawalIds = strings.Join(ids, ",")
		call.WithdrawedAt = sql.NullTime{}
	}

	if len(transfers) > 0 {
		transferTx, err := node.solanaClient().TransferTokens(ctx, node.conf.SolanaKey, mtgUser.Public, nonce.Account(), transfers)
		if err != nil {
			panic(err)
		}
		if len(mintKeys) > 0 {
			_, err = tx.PartialSign(solanaApp.BuildSignersGetter(mintKeys...))
			if err != nil {
				panic(err)
			}
		}
		id := common.UniqueId(req.Id, store.CallTypePrepare)
		calls = append(calls, &store.SystemCall{
			RequestId:       id,
			Superior:        req.Id,
			Type:            store.CallTypePrepare,
			Public:          mtgUser.Public,
			Message:         transferTx.Message.ToBase64(),
			Raw:             transferTx.MustToBase64(),
			State:           common.RequestStateInitial,
			WithdrawalIds:   "",
			WithdrawedAt:    sql.NullTime{Valid: true, Time: req.CreatedAt},
			Signature:       sql.NullString{Valid: false},
			RequestSignerAt: sql.NullTime{Valid: false},
			CreatedAt:       req.CreatedAt,
			UpdatedAt:       req.CreatedAt,
		})
	}
	calls = append(calls, &call)

	err = node.store.WriteUnfinishedSystemCallWithRequest(ctx, req, calls, store.DeployedAssetsFromTransferTokens(transfers), txs, compaction)
	logger.Printf("solana.WriteUnfinishedSystemCallWithRequest(%v %d %s) => %v", call, len(txs), compaction, err)
	if err != nil {
		panic(err)
	}

	return txs, compaction
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
		id := common.UniqueId(req.Id, fmt.Sprintf("%8d", i))
		id = common.UniqueId(id, fmt.Sprintf("MTG:%v:%d", members, threshold))
		sessions = append(sessions, &store.Session{
			Id:         id,
			MixinHash:  req.MixinHash.String(),
			MixinIndex: req.Output.OutputIndex,
			Index:      i,
			Operation:  OperationTypeKeygenInput,
			CreatedAt:  req.Output.SequencerCreatedAt,
		})
	}

	err := node.store.WriteSessionsWithRequest(ctx, req, sessions, false)
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
	account, err := node.store.ReadFirstGeneratedNonceAccount(ctx)
	logger.Printf("store.ReadFirstGeneratedNonceAccount() => %s %v", account, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadFirstGeneratedNonceAccount() => %v", err))
	} else if account == "" || oldAccount.Address != account {
		return node.failRequest(ctx, req, "")
	}

	err = node.store.WriteSignerUserWithRequest(ctx, req, node.conf.SolanaDepositEntry, key, account)
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
		rid := uuid.Must(uuid.FromBytes(extra)).String()
		call, err := node.store.ReadInitialSystemCallBySuperior(ctx, rid)
		if err != nil {
			panic(err)
		}
		if call.WithdrawedAt.Valid {
			return node.failRequest(ctx, req, "")
		}

		err = node.store.MarkSystemCallWithdrawedWithRequest(ctx, req, call)
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

func (node *Node) processSignerSignatureResponse(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleSigner {
		panic(req.Role)
	}
	if req.Action != OperationTypeSignOutput {
		panic(req.Action)
	}

	return nil, ""
}
