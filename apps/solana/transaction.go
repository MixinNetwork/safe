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

func (c *Client) TransferOrMintTokens(ctx context.Context, payer, mtg solana.PublicKey, nonce NonceAccount, transfers []TokenTransfers) (*solana.Transaction, error) {
	builder, payerAdress := buildInitialTxWithNonceAccount(payer, nonce)

	var nullFreezeAuthority solana.PublicKey
	var rent uint64
	for _, transfer := range transfers {
		if transfer.SolanaAsset {
			b, err := c.addTransferSolanaAssetInstruction(ctx, builder, &transfer, payerAdress, mtg)
			if err != nil {
				return nil, err
			}
			builder = b
			continue
		}

		if common.CheckTestEnvironment(ctx) && transfer.AssetId == common.SafeLitecoinChainId {
			transfer.Mint = solana.MustPublicKeyFromBase58("EFShFtXaMF1n1f6k3oYRd81tufEXzUuxYM6vkKrChVs8")
		}
		mint := transfer.Mint
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
					payerAdress,
					mint,
				).Build(),
			)
			builder.AddInstruction(
				token.NewInitializeMint2Instruction(
					transfer.Decimals,
					mtg,
					nullFreezeAuthority,
					mint,
				).Build(),
			)
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
					payerAdress,
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
				mtg,
				nil,
			).Build(),
		)
	}

	tx, err := builder.Build()
	if err != nil {
		panic(err)
	}
	if common.CheckTestEnvironment(ctx) && transfers[0].AssetId == common.SafeLitecoinChainId {
		tx.Signatures = make([]solana.Signature, tx.Message.Header.NumRequiredSignatures)
		tx.Signatures[1] = solana.MustSignatureFromBase58("449h9tg5hCHigegVuH6Waoh8ACDYc5hrhZh2t9td2ToFgtBHrkzH7Z2vSE2nnmNdksUkj71k7eaQhdHrRgj19b5W")
	}
	return tx, nil
}

func (c *Client) TransferOrBurnTokens(ctx context.Context, payer, user solana.PublicKey, nonce NonceAccount, transfers []*TokenTransfers) (*solana.Transaction, error) {
	builder, payerAdress := buildInitialTxWithNonceAccount(payer, nonce)

	for _, transfer := range transfers {
		if transfer.SolanaAsset {
			if transfer.AssetId == transfer.ChainId {
				builder.AddInstruction(
					system.NewTransferInstruction(
						transfer.Amount,
						user,
						transfer.Destination,
					).Build(),
				)
			} else {
				src, _, err := solana.FindAssociatedTokenAddress(user, transfer.Mint)
				if err != nil {
					return nil, err
				}
				dst, _, err := solana.FindAssociatedTokenAddress(transfer.Destination, transfer.Mint)
				if err != nil {
					return nil, err
				}
				ata, err := c.RPCGetAccount(ctx, dst)
				if err != nil {
					return nil, err
				}
				if ata == nil || common.CheckTestEnvironment(ctx) {
					builder.AddInstruction(
						tokenAta.NewCreateInstruction(
							payerAdress,
							transfer.Destination,
							transfer.Mint,
						).Build(),
					)
				}
				builder.AddInstruction(
					token.NewTransferCheckedInstruction(
						transfer.Amount,
						transfer.Decimals,
						src,
						transfer.Mint,
						dst,
						user,
						nil,
					).Build(),
				)
			}
			continue
		}

		ataAddress, _, err := solana.FindAssociatedTokenAddress(user, transfer.Mint)
		if err != nil {
			return nil, err
		}
		builder.AddInstruction(
			token.NewBurnCheckedInstruction(
				transfer.Amount,
				transfer.Decimals,
				ataAddress,
				transfer.Mint,
				user,
				nil,
			).Build(),
		)
	}

	return builder.Build()
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

func (c *Client) addTransferSolanaAssetInstruction(ctx context.Context, builder *solana.TransactionBuilder, transfer *TokenTransfers, payer, source solana.PublicKey) (*solana.TransactionBuilder, error) {
	if !transfer.SolanaAsset {
		return builder, nil
	}
	if transfer.AssetId == transfer.ChainId {
		builder.AddInstruction(
			system.NewTransferInstruction(
				transfer.Amount,
				source,
				transfer.Destination,
			).Build(),
		)
		return builder, nil
	}

	src, _, err := solana.FindAssociatedTokenAddress(source, transfer.Mint)
	if err != nil {
		return nil, err
	}
	dst, _, err := solana.FindAssociatedTokenAddress(transfer.Destination, transfer.Mint)
	if err != nil {
		return nil, err
	}
	ata, err := c.RPCGetAccount(ctx, dst)
	if err != nil {
		return nil, err
	}
	if ata == nil || common.CheckTestEnvironment(ctx) {
		builder.AddInstruction(
			tokenAta.NewCreateInstruction(
				payer,
				transfer.Destination,
				transfer.Mint,
			).Build(),
		)
	}
	builder.AddInstruction(
		token.NewTransferCheckedInstruction(
			transfer.Amount,
			transfer.Decimals,
			src,
			transfer.Mint,
			dst,
			source,
			nil,
		).Build(),
	)
	return builder, nil
}
