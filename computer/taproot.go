package computer

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/taproot"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost"
	"github.com/MixinNetwork/safe/common"
)

const (
	taprootKeygenRoundTimeout = time.Minute
	taprootSignRoundTimeout   = time.Minute
)

func (node *Node) taprootKeygen(ctx context.Context, sessionId []byte) (*KeygenResult, error) {
	logger.Printf("node.taprootKeygen(%x)", sessionId)
	start, err := frost.KeygenTaproot(node.id, node.GetPartySlice(), node.threshold)(sessionId)
	if err != nil {
		return nil, fmt.Errorf("frost.KeygenTaproot(%x) => %v", sessionId, err)
	}

	keygenResult, err := node.handlerLoop(ctx, start, sessionId, taprootKeygenRoundTimeout)
	if err != nil {
		return nil, fmt.Errorf("node.handlerLoop(%x) => %v", sessionId, err)
	}
	keygenConfig := keygenResult.(*frost.TaprootConfig)

	return &KeygenResult{
		Public: keygenConfig.PublicKey,
		Share:  common.MarshalPanic(keygenConfig),
		SSID:   start.SSID(),
	}, nil
}

func (node *Node) taprootSign(ctx context.Context, members []party.ID, public string, share []byte, m []byte, sessionId []byte) (*SignResult, error) {
	logger.Printf("node.taprootSign(%x, %s, %x, %v)", sessionId, public, m, members)
	group := curve.Secp256k1{}
	conf := &frost.TaprootConfig{PrivateShare: group.NewScalar()}
	err := conf.UnmarshalBinary(share)
	if err != nil {
		panic(err)
	}
	if hex.EncodeToString(conf.PublicKey) != public {
		panic(public)
	}

	start, err := frost.SignTaproot(conf, members, m)(sessionId)
	if err != nil {
		return nil, fmt.Errorf("frost.SignTaproot(%x, %x) => %v", sessionId, m, err)
	}

	signResult, err := node.handlerLoop(ctx, start, sessionId, taprootSignRoundTimeout)
	if err != nil {
		return nil, err
	}
	signature := signResult.(taproot.Signature)
	logger.Printf("node.taprootSign(%x, %s, %x) => %v", sessionId, public, m, signature)
	if !conf.PublicKey.Verify(signature, m) {
		return nil, fmt.Errorf("node.taprootSign(%x, %s, %x) => %v verify", sessionId, public, m, signature)
	}

	return &SignResult{
		Signature: signature,
		SSID:      start.SSID(),
	}, nil
}
