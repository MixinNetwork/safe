package computer

import (
	"context"
	"fmt"
	"math/big"

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
			Operation:  OperationTypeKeygenInput,
			CreatedAt:  req.Output.SequencerCreatedAt,
		})
	}

	err := node.store.WriteSessionsWithRequest(ctx, req, sessions, true)
	if err != nil {
		panic(fmt.Errorf("store.FailRequest(%v) => %v", req, err))
	}
	return nil, ""
}
