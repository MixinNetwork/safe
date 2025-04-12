package solana

import (
	"encoding/hex"
	"fmt"

	solana "github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58"
)

func MPK(public string) solana.PublicKey {
	key, err := PublicKeyFromString(public)
	if err != nil {
		panic(err)
	}

	return key
}

func PublicKeyFromString(public string) (solana.PublicKey, error) {
	b, err := base58.Decode(public)
	if err != nil || len(b) != solana.PublicKeyLength {
		b, err = hex.DecodeString(public)
	}

	if len(b) != solana.PublicKeyLength {
		return solana.PublicKey{}, fmt.Errorf("invalid public key length %d", len(b))
	}

	return solana.PublicKeyFromBytes(b), nil
}

func VerifyHolderKey(public string) error {
	_, err := PublicKeyFromString(public)
	return err
}

func VerifyMessageSignature(public string, msg, signature []byte) error {
	pub, err := PublicKeyFromString(public)
	if err != nil {
		return err
	}

	sig := solana.SignatureFromBytes(signature)
	if pub.Verify(msg, sig) {
		return nil
	}

	return fmt.Errorf("solana.VerifyMessageSignature(%s, %x, %x)", public, msg, signature)
}
