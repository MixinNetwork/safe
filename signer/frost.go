package signer

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost/sign"
	"github.com/MixinNetwork/safe/common"
)

const (
	frostKeygenRoundTimeout = 5 * time.Minute
	frostSignRoundTimeout   = 5 * time.Minute
)

func (node *Node) frostKeygen(ctx context.Context, sessionId []byte, group curve.Curve) (*KeygenResult, error) {
	logger.Printf("node.frostKeygen(%x)", sessionId)
	start, err := frost.Keygen(group, node.id, node.members, node.threshold)(sessionId)
	if err != nil {
		return nil, fmt.Errorf("frost.Keygen(%x) => %v", sessionId, err)
	}

	keygenResult, err := node.handlerLoop(ctx, start, sessionId, frostKeygenRoundTimeout)
	if err != nil {
		return nil, fmt.Errorf("node.handlerLoop(%x) => %v", sessionId, err)
	}
	keygenConfig := keygenResult.(*frost.Config)

	return &KeygenResult{
		Public: common.MarshalPanic(keygenConfig.PublicPoint()),
		Share:  common.MarshalPanic(keygenConfig),
		SSID:   start.SSID(),
	}, nil
}

func (node *Node) frostSign(ctx context.Context, public string, share []byte, m []byte, sessionId []byte, group curve.Curve, variant int) (*SignResult, error) {
	logger.Printf("node.frostSign(%x, %s, %x)", sessionId, public, m)
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

	if variant == sign.ProtocolMixinPublic {
		if len(m) < 32 {
			return nil, fmt.Errorf("invalid message %d", len(m))
		}
		r := group.NewScalar()
		err = r.UnmarshalBinary(m[:32])
		if err != nil {
			return nil, fmt.Errorf("invalid message %x", m[:32])
		}
		P = r.ActOnBase().Add(P)
	}

	start, err := frost.Sign(conf, node.members, m, variant)(sessionId)
	if err != nil {
		return nil, fmt.Errorf("frost.Sign(%x, %x) => %v", sessionId, m, err)
	}

	signResult, err := node.handlerLoop(ctx, start, sessionId, frostSignRoundTimeout)
	if err != nil {
		return nil, fmt.Errorf("node.handlerLoop(%x) => %v", sessionId, err)
	}
	signature := signResult.(*frost.Signature)
	logger.Printf("node.frostSign(%x, %s, %x) => %v", sessionId, public, m, signature)
	if variant == sign.ProtocolMixinPublic {
		m = m[32:]
	}
	if !signature.VerifyEd25519(P, m) {
		return nil, fmt.Errorf("node.frostSign(%x, %s, %x) => %v verify", sessionId, public, m, signature)
	}

	return &SignResult{
		Signature: signature.Serialize(),
		SSID:      start.SSID(),
	}, nil
}
