package common

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/gofrs/uuid/v5"
)

func ECDHEd25519(priv, pub string) [32]byte {
	a, err := crypto.KeyFromString(priv)
	if err != nil {
		panic(err)
	}
	B, err := crypto.KeyFromString(pub)
	if err != nil {
		panic(err)
	}
	R := crypto.KeyMultPubPriv(&B, &a)
	return crypto.NewHash(R.Bytes())
}

func AESDecrypt(secret, b []byte) []byte {
	aes, err := aes.NewCipher(secret)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}
	nonce := b[:aead.NonceSize()]
	cipher := b[aead.NonceSize():]
	d, err := aead.Open(nil, nonce, cipher, nil)
	if err != nil {
		panic(err)
	}
	return append(nonce, d...)
}

func AESEncrypt(secret, b []byte, sid string) []byte {
	if len(b) < 16 {
		panic(sid)
	}
	if uuid.Must(uuid.FromBytes(b[:16])).String() != sid {
		panic(sid)
	}
	aes, err := aes.NewCipher(secret)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}
	nonce := b[:aead.NonceSize()]
	cipher := aead.Seal(nil, nonce, b[aead.NonceSize():], nil)
	return append(nonce, cipher...)
}
