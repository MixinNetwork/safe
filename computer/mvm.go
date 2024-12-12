package computer

import (
	"context"
	"fmt"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	solana "github.com/gagliardetto/solana-go"
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
