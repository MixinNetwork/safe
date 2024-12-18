package computer

import (
	"context"

	solana "github.com/gagliardetto/solana-go"
)

func (node *Node) CreateNonceAccount(ctx context.Context) (*solana.PublicKey, *solana.Hash, error) {
	nonce, err := solana.NewRandomPrivateKey()
	if err != nil {
		panic(err)
	}

	client := node.solanaClient()
	tx, err := client.CreateNonceAccount(ctx, node.conf.SolanaKey, nonce.String(), "", 0)
	if err != nil {
		return nil, nil, err
	}
	err = client.SendAndConfirmTransaction(ctx, tx)
	if err != nil {
		return nil, nil, err
	}

	hash, err := client.GetNonceAccountHash(ctx, nonce.PublicKey())
	if err != nil {
		return nil, nil, err
	}
	pub := nonce.PublicKey()

	return &pub, hash, nil
}
