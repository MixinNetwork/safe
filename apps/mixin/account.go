package mixin

import (
	"encoding/hex"
	"fmt"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
)

func VerifyPublicKey(pub string) error {
	key, err := crypto.KeyFromString(pub)
	if err != nil {
		return err
	}
	if !key.CheckKey() {
		return fmt.Errorf("invalid mixin public key %s", pub)
	}
	return nil
}

func VerifySignature(public string, msg, sig []byte) error {
	var msig crypto.Signature
	if len(sig) != len(msig) {
		return fmt.Errorf("invalid mixin signature %x", sig)
	}
	copy(msig[:], sig)
	key, err := crypto.KeyFromString(public)
	if err != nil {
		return err
	}
	if key.Verify(msg, msig) {
		return nil
	}
	return fmt.Errorf("mixin.VerifySignature(%s, %x, %x)", public, msg, sig)
}

func DeriveKey(signer string, mask []byte) string {
	group := curve.Edwards25519{}
	r := group.NewScalar()
	err := r.UnmarshalBinary(mask)
	if err != nil {
		panic(err)
	}
	key, err := crypto.KeyFromString(signer)
	if err != nil || !key.CheckKey() {
		panic(signer)
	}
	P := group.NewPoint()
	err = P.UnmarshalBinary(key[:])
	if err != nil {
		panic(err)
	}
	P = r.ActOnBase().Add(P)
	b, err := P.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func ParseAddress(s string) (*common.Address, error) {
	addr, err := common.NewAddressFromString(s)
	return &addr, err
}

func BuildAddress(holder, signer, observer string) *common.Address {
	for _, k := range []string{holder, signer, observer} {
		err := VerifyPublicKey(k)
		if err != nil {
			panic(k)
		}
	}
	seed := crypto.NewHash([]byte(holder + signer + observer))
	view := crypto.NewKeyFromSeed(append(seed[:], seed[:]...))
	publicSpend, _ := crypto.KeyFromString(signer)
	return &common.Address{
		PublicSpendKey: publicSpend,
		PublicViewKey:  view.Public(),
		PrivateViewKey: view,
	}
}
