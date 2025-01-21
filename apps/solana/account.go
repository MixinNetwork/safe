package solana

import (
	"github.com/MixinNetwork/safe/common"
	solana "github.com/gagliardetto/solana-go"
)

func PublicKeyFromEd25519Public(pub string) solana.PublicKey {
	return solana.PublicKeyFromBytes(common.DecodeHexOrPanic(pub))
}
