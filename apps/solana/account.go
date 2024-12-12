package solana

import (
	"fmt"

	solana "github.com/gagliardetto/solana-go"
)

func VerifyHolderKey(public string) error {
	_, err := solana.PublicKeyFromBase58(public)
	return err
}

func VerifyMessageSignature(public string, msg, signature []byte) error {
	pub := solana.MustPublicKeyFromBase58(public)
	sig := solana.SignatureFromBytes(signature)

	if pub.Verify(msg, sig) {
		return nil
	}

	return fmt.Errorf("solana.VerifyMessageSignature(%s, %x, %x)", public, msg, signature)
}
