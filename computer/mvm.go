package computer

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	mc "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	solana "github.com/gagliardetto/solana-go"
)

const (
	SignerKeygenMaximum = 128
)

func (node *Node) startProcess(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleUser {
		panic(req.Role)
	}

	ab := req.ExtraBytes()
	if len(ab) != 32 {
		logger.Printf("startProcess(%v) => invalid program address bytes length %d", req.Id, len(ab))
		return node.failRequest(ctx, req, "")
	}

	address := solana.PublicKeyFromBytes(ab).String()
	old, err := node.store.ReadProgramByAddress(ctx, address)
	logger.Printf("store.ReadProgramByAddress(%s) => %v %v", address, old, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadProgramByAddress(%s) => %v", address, err))
	} else if old != nil {
		return node.failRequest(ctx, req, "")
	}

	err = node.store.WriteProgramWithRequest(ctx, req, address)
	if err != nil {
		panic(fmt.Errorf("store.WriteProgramWithRequest(%v %s) => %v", req, address, err))
	}
	return nil, ""
}

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
