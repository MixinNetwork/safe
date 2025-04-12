package solana

import (
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/assert"
)

func TestVerifyPublic(t *testing.T) {
	public := "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b"
	err := VerifyHolderKey(public)
	assert.Nil(t, err)

	key1, err := solana.NewRandomPrivateKey()
	assert.Nil(t, err)
	pub1 := key1.PublicKey()
	t.Log(key1.String(), pub1.String())

	key2, err := solana.NewRandomPrivateKey()
	assert.Nil(t, err)
	pub2 := key2.PublicKey()
	t.Log(key2.String(), pub2.String())

	pri3, err := solana.NewRandomPrivateKey()
	assert.Nil(t, err)
	pub3 := pri3.PublicKey()
	t.Log(pri3.String(), pub3.String())
}
