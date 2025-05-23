package mixin

import (
	"crypto/ed25519"
	"encoding/hex"
	"slices"

	"filippo.io/edwards25519"
	"github.com/MixinNetwork/mixin/crypto"
)

const OutputTypeWithdrawalClaim = 0xa9

func CheckEd25519ValidChildPath(path []byte) bool {
	return slices.ContainsFunc(path, func(b byte) bool {
		return b > 0
	})
}

func DeriveEd25519Child(public string, path []byte) ed25519.PublicKey {
	master, err := crypto.KeyFromString(public)
	if err != nil || !master.CheckKey() {
		panic(err)
	}
	if !CheckEd25519ValidChildPath(path) {
		panic(hex.EncodeToString(path))
	}

	seed := crypto.Sha256Hash(append(master[:], path...))
	child := crypto.NewKeyFromSeed(append(seed[:], seed[:]...)).Public()

	p1, err := edwards25519.NewIdentityPoint().SetBytes(master[:])
	if err != nil {
		panic(err)
	}
	p2, err := edwards25519.NewIdentityPoint().SetBytes(child[:])
	if err != nil {
		panic(err)
	}
	res := edwards25519.NewIdentityPoint().Add(p1, p2)
	return ed25519.PublicKey(res.Bytes())
}
