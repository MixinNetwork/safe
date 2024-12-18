package solana

import (
	"context"
	"fmt"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	confirm "github.com/gagliardetto/solana-go/rpc/sendAndConfirmTransaction"
)

const (
	nonceAccountSize uint64 = 80
)

func (c *Client) CreateNonceAccount(ctx context.Context, key, nonce, hash string, rent uint64) (*solana.Transaction, error) {
	client := c.getRPCClient()
	payer, err := solana.PrivateKeyFromBase58(key)
	if err != nil {
		panic(err)
	}
	nonceKey, err := solana.PrivateKeyFromBase58(nonce)
	if err != nil {
		panic(err)
	}

	var rentExemptBalance uint64
	if rent > 0 {
		rentExemptBalance = rent
	} else {
		rentExemptBalance, err = client.GetMinimumBalanceForRentExemption(
			ctx,
			nonceAccountSize,
			rpc.CommitmentFinalized,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get rent exempt balance: %w", err)
		}
	}
	var blockhash solana.Hash
	if hash != "" {
		blockhash = solana.MustHashFromBase58(hash)
	} else {
		block, err := client.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
		if err != nil {
			return nil, fmt.Errorf("solana.GetLatestBlockhash() => %v", err)
		}
		blockhash = block.Value.Blockhash
	}

	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			system.NewCreateAccountInstruction(
				rentExemptBalance,
				nonceAccountSize,
				system.ProgramID,
				payer.PublicKey(),
				nonceKey.PublicKey(),
			).Build(),
			system.NewInitializeNonceAccountInstruction(
				payer.PublicKey(),
				nonceKey.PublicKey(),
				solana.SysVarRecentBlockHashesPubkey,
				solana.SysVarRentPubkey,
			).Build(),
		},
		blockhash,
		solana.TransactionPayer(payer.PublicKey()),
	)
	if err != nil {
		panic(err)
	}
	if _, err := tx.Sign(BuildSignersGetter(nonceKey, payer)); err != nil {
		panic(err)
	}
	return tx, nil
}

func (c *Client) SendAndConfirmTransaction(ctx context.Context, tx *solana.Transaction) error {
	client := c.getRPCClient()
	ws, err := c.connectWs(ctx)
	if err != nil {
		return fmt.Errorf("solana.connectWs() => %v", err)
	}
	defer ws.Close()

	if _, err := confirm.SendAndConfirmTransaction(ctx, client, ws, tx); err != nil {
		return fmt.Errorf("solana.SendAndConfirmTransaction() => %v", err)
	}
	return nil
}
