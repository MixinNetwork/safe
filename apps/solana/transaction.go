package solana

import (
	"context"
	"fmt"

	"github.com/MixinNetwork/safe/common"
	solana "github.com/gagliardetto/solana-go"
	tokenAta "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	confirm "github.com/gagliardetto/solana-go/rpc/sendAndConfirmTransaction"
)

const (
	nonceAccountSize uint64 = 80
	mintSize         uint64 = 82
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

func (c *Client) TransferTokens(ctx context.Context, payerKey, mtgKey string, nonce NonceAccount, transfers []TokenTransfers) (*solana.Transaction, error) {
	builder, payer := buildInitialTxWithNonceAccount(payerKey, nonce)
	mtg := solana.MustPrivateKeyFromBase58(mtgKey)
	signers := []solana.PrivateKey{payer, mtg}

	var nullFreezeAuthority solana.PublicKey
	var rent uint64
	for _, transfer := range transfers {
		if transfer.IsSol {
			builder.AddInstruction(
				system.NewTransferInstruction(
					transfer.Amount,
					mtg.PublicKey(),
					transfer.Destination,
				).Build(),
			)
			continue
		}

		mint := transfer.Mint.PublicKey()
		mintToken, err := c.GetMint(ctx, mint)
		if err != nil {
			return nil, err
		}
		if mintToken == nil || common.CheckTestEnvironment(ctx) {
			if rent == 0 {
				rent, err = c.getRPCClient().GetMinimumBalanceForRentExemption(
					ctx,
					mintSize,
					rpc.CommitmentFinalized,
				)
				if err != nil {
					return nil, fmt.Errorf("failed to get rent exempt balance: %w", err)
				}
			}
			builder.AddInstruction(
				system.NewCreateAccountInstruction(
					rent,
					mintSize,
					token.ProgramID,
					payer.PublicKey(),
					mint,
				).Build(),
			)
			builder.AddInstruction(
				token.NewInitializeMint2Instruction(
					transfer.Decimals,
					mtg.PublicKey(),
					nullFreezeAuthority,
					mint,
				).Build(),
			)
			signers = append(signers, transfer.Mint)
		}

		ataAddress, _, err := solana.FindAssociatedTokenAddress(transfer.Destination, mint)
		if err != nil {
			return nil, err
		}
		ata, err := c.RPCGetAccount(ctx, ataAddress)
		if err != nil {
			return nil, err
		}
		if ata == nil || common.CheckTestEnvironment(ctx) {
			builder.AddInstruction(
				tokenAta.NewCreateInstruction(
					payer.PublicKey(),
					transfer.Destination,
					mint,
				).Build(),
			)
		}

		builder.AddInstruction(
			token.NewMintToInstruction(
				transfer.Amount,
				mint,
				ataAddress,
				mtg.PublicKey(),
				nil,
			).Build(),
		)
	}

	tx, err := builder.Build()
	if err != nil {
		panic(err)
	}
	if _, err := tx.Sign(BuildSignersGetter(signers...)); err != nil {
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
