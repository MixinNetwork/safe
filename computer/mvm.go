package computer

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	mc "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/logger"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	solana "github.com/gagliardetto/solana-go"
	"github.com/shopspring/decimal"
)

const (
	SignerKeygenMaximum = 128
)

func (node *Node) addUser(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
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

func (node *Node) systemCall(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleUser {
		panic(req.Role)
	}
	if req.AssetId != mtg.StorageAssetId {
		return node.failRequest(ctx, req, "")
	}
	mtgUser, err := node.store.ReadUser(ctx, store.MPCUserId)
	logger.Printf("store.ReadUser(%s) => %v %v", store.MPCUserId.String(), mtgUser, err)
	if err != nil {
		panic(err)
	}
	nonce, err := node.store.ReadNonceAccount(ctx, mtgUser.NonceAccount)
	logger.Printf("store.ReadNonceAccount(%s) => %v %v", mtgUser.NonceAccount, nonce, err)
	if err != nil {
		panic(err)
	}

	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, req.MixinHash.String())
	if err != nil {
		panic(err)
	}

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
	tx, err := solana.TransactionFromBytes(data[4:])
	logger.Printf("solana.TransactionFromBytes(%x) => %v %v", data[4:], tx, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	call := store.SystemCall{
		RequestId: req.Id,
		UserId:    user.Id().String(),
		Raw:       hex.EncodeToString(data[4:]),
		State:     store.SystemCallStateInitial,
		CreatedAt: req.CreatedAt,
		UpdatedAt: req.CreatedAt,
	}

	destination := solanaApp.PublicKeyFromEd25519Public(user.Public)
	withdraws := [][2]string{}
	transfers := []solanaApp.TokenTransfers{}
	for _, ref := range ver.References {
		ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, ref.String())
		if err != nil {
			panic(err)
		}
		if ver == nil {
			continue
		}

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
			key, err := node.store.GetSpareKey(ctx)
			if err != nil {
				panic(err)
			}
			transfers = append(transfers, solanaApp.TokenTransfers{
				SolanaAsset: false,
				Mint:        solanaApp.PublicKeyFromEd25519Public(key.Public),
				Destination: destination,
				Amount:      total.BigInt().Uint64(),
				Decimals:    uint8(asset.Precision),
			})
			continue
		}

		transfers = append(transfers, solanaApp.TokenTransfers{
			SolanaAsset: true,
			Destination: destination,
			Amount:      total.BigInt().Uint64(),
			Decimals:    uint8(9),
		})
		withdraws = append(withdraws, [2]string{asset.AssetID, total.String()})
	}

	var txs []*mtg.Transaction
	var compaction string
	var subCalls []store.SubCall
	if len(withdraws) > 0 {
		// TODO build withdrawal txs with mtg
	} else {
		call.State = store.SystemCallStateWithdrawed
		tx, mints, err := node.solanaClient().TransferTokens(ctx, node.conf.SolanaKey, mtgUser.Public, solanaApp.NonceAccount{
			Address: solana.MustPublicKeyFromBase58(nonce.Address),
			Hash:    solana.MustHashFromBase58(nonce.Hash),
		}, transfers)
		if err != nil {
			panic(err)
		}
		subCalls = append(subCalls, store.SubCall{
			Message:   tx.Message.ToBase64(),
			RequestId: req.Id,
			UserId:    user.Id().String(),
			Mints:     strings.Join(mints, ","),
			Raw:       tx.MustToBase64(),
			State:     store.SystemCallStateInitial,
			CreatedAt: req.CreatedAt,
			UpdatedAt: req.CreatedAt,
		})
	}

	err = node.store.WriteUnfinishedSystemCallWithRequest(ctx, req, call, subCalls, txs, compaction)
	logger.Printf("solana.WriteUnfinishedSystemCallWithRequest(%v %d %d %s) => %v", call, len(subCalls), len(txs), compaction, err)
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
