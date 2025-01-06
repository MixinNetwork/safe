package computer

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost/sign"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
)

const (
	frostKeygenRoundTimeout = 5 * time.Minute
	frostSignRoundTimeout   = 5 * time.Minute
)

func (node *Node) frostKeygen(ctx context.Context, sessionId []byte, group curve.Curve) (*store.KeygenResult, error) {
	logger.Printf("node.frostKeygen(%x)", sessionId)
	start, err := frost.Keygen(group, node.id, node.GetPartySlice(), node.threshold)(sessionId)
	if err != nil {
		return nil, fmt.Errorf("frost.Keygen(%x) => %v", sessionId, err)
	}

	keygenResult, err := node.handlerLoop(ctx, start, sessionId, frostKeygenRoundTimeout)
	if err != nil {
		return nil, fmt.Errorf("node.handlerLoop(%x) => %v", sessionId, err)
	}
	keygenConfig := keygenResult.(*frost.Config)

	return &store.KeygenResult{
		Public: common.MarshalPanic(keygenConfig.PublicPoint()),
		Share:  common.MarshalPanic(keygenConfig),
		SSID:   start.SSID(),
	}, nil
}

func (node *Node) frostSign(ctx context.Context, members []party.ID, public string, share []byte, m []byte, sessionId []byte, group curve.Curve) (*store.SignResult, error) {
	logger.Printf("node.frostSign(%x, %s, %x, %v)", sessionId, public, m, members)
	conf := frost.EmptyConfig(group)
	err := conf.UnmarshalBinary(share)
	if err != nil {
		panic(err)
	}
	P := conf.PublicPoint()
	pb := common.MarshalPanic(P)
	if hex.EncodeToString(pb) != public {
		panic(public)
	}

	start, err := frost.Sign(conf, members, m, sign.ProtocolEd25519SHA512)(sessionId)
	if err != nil {
		return nil, fmt.Errorf("frost.Sign(%x, %x) => %v", sessionId, m, err)
	}

	signResult, err := node.handlerLoop(ctx, start, sessionId, frostSignRoundTimeout)
	if err != nil {
		return nil, fmt.Errorf("node.handlerLoop(%x) => %v", sessionId, err)
	}
	signature := signResult.(*frost.Signature)
	logger.Printf("node.frostSign(%x, %s, %x) => %v", sessionId, public, m, signature)
	if !signature.VerifyEd25519(P, m) {
		return nil, fmt.Errorf("node.frostSign(%x, %s, %x) => %v verify", sessionId, public, m, signature)
	}

	return &store.SignResult{
		Signature: signature.Serialize(),
		SSID:      start.SSID(),
	}, nil
}
