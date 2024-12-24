package signer

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/ecdsa"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/protocols/cmp"
	"github.com/MixinNetwork/safe/common"
)

const (
	cmpKeygenRoundTimeout = 5 * time.Minute
	cmpSignRoundTimeout   = 5 * time.Minute
)

func (node *Node) cmpKeygen(ctx context.Context, sessionId []byte, crv byte) (*KeygenResult, error) {
	logger.Printf("node.cmpKeygen(%x)", sessionId)
	start, err := cmp.Keygen(curve.Secp256k1{}, node.id, node.GetPartySlice(), node.threshold, nil)(sessionId)
	if err != nil {
		return nil, fmt.Errorf("cmp.Keygen(%x) => %v", sessionId, err)
	}

	keygenResult, err := node.handlerLoop(ctx, start, sessionId, cmpKeygenRoundTimeout)
	if err != nil {
		return nil, fmt.Errorf("node.handlerLoop(%x) => %v", sessionId, err)
	}
	keygenConfig := keygenResult.(*cmp.Config)

	return &KeygenResult{
		Public: common.MarshalPanic(keygenConfig.PublicPoint()),
		Share:  common.MarshalPanic(keygenConfig),
		SSID:   start.SSID(),
	}, nil
}

func (node *Node) cmpSign(ctx context.Context, members []party.ID, public string, share []byte, m []byte, sessionId []byte, crv byte, path []byte) (*SignResult, error) {
	logger.Printf("node.cmpSign(%x, %s, %x, %d, %x, %v)", sessionId, public, m, crv, path, members)
	conf := cmp.EmptyConfig(curve.Secp256k1{})
	err := conf.UnmarshalBinary(share)
	if err != nil {
		panic(err)
	}
	pb := common.MarshalPanic(conf.PublicPoint())
	if hex.EncodeToString(pb) != public {
		panic(public)
	}
	for i := 0; i < int(path[0]); i++ {
		conf, err = conf.DeriveBIP32(uint32(path[i+1]))
		if err != nil {
			return nil, fmt.Errorf("cmp.DeriveBIP32(%x, %d, %d) => %v", sessionId, i, path[i+1], err)
		}
		pb := common.MarshalPanic(conf.PublicPoint())
		if hex.EncodeToString(pb) == public {
			panic(public)
		}
	}

	start, err := cmp.Sign(conf, members, m, nil)(sessionId)
	if err != nil {
		return nil, fmt.Errorf("cmp.Sign(%x, %x) => %v", sessionId, m, err)
	}

	signResult, err := node.handlerLoop(ctx, start, sessionId, cmpSignRoundTimeout)
	if err != nil {
		return nil, fmt.Errorf("node.handlerLoop(%x) => %v", sessionId, err)
	}
	signature := signResult.(*ecdsa.Signature)
	logger.Printf("node.cmpSign(%x, %s, %x) => %v", sessionId, public, m, signature)
	if !signature.Verify(conf.PublicPoint(), m) {
		return nil, fmt.Errorf("node.cmpSign(%x, %s, %x) => %v verify", sessionId, public, m, signature)
	}

	res := &SignResult{SSID: start.SSID()}
	switch crv {
	case common.CurveSecp256k1ECDSABitcoin:
		res.Signature = signature.SerializeDER()
	case common.CurveSecp256k1ECDSAEthereum:
		res.Signature = signature.SerializeEthereum()
	default:
		panic(crv)
	}
	return res, nil
}
