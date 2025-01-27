package solana

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/MixinNetwork/safe/common"
	"github.com/gagliardetto/solana-go"
	tokenAta "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
)

const (
	nonceAccountSize uint64 = 80
	mintSize         uint64 = 82
)

func (c *Client) CreateNonceAccount(ctx context.Context, key, nonce string) (*solana.Transaction, error) {
	client := c.getRPCClient()
	payer, err := solana.PrivateKeyFromBase58(key)
	if err != nil {
		panic(err)
	}
	nonceKey, err := solana.PrivateKeyFromBase58(nonce)
	if err != nil {
		panic(err)
	}

	rentExemptBalance, err := client.GetMinimumBalanceForRentExemption(
		ctx,
		nonceAccountSize,
		rpc.CommitmentConfirmed,
	)
	if err != nil {
		return nil, fmt.Errorf("soalan.GetMinimumBalanceForRentExemption(%d) => %v", nonceAccountSize, err)
	}
	block, err := client.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return nil, fmt.Errorf("solana.GetLatestBlockhash() => %v", err)
	}
	blockhash := block.Value.Blockhash

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
	_, err = tx.Sign(BuildSignersGetter(nonceKey, payer))
	if err != nil {
		panic(err)
	}
	return tx, nil
}

func (c *Client) TransferOrMintTokens(ctx context.Context, payer, mtg solana.PublicKey, nonce NonceAccount, transfers []TokenTransfers) (*solana.Transaction, error) {
	builder := buildInitialTxWithNonceAccount(payer, nonce)

	var nullFreezeAuthority solana.PublicKey
	for _, transfer := range transfers {
		if transfer.SolanaAsset {
			b, err := c.addTransferSolanaAssetInstruction(ctx, builder, &transfer, payer, mtg)
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
			rent, err := c.getRPCClient().GetMinimumBalanceForRentExemption(
				ctx,
				mintSize,
				rpc.CommitmentConfirmed,
			)
			if err != nil {
				return nil, fmt.Errorf("soalan.GetMinimumBalanceForRentExemption(%d) => %v", nonceAccountSize, err)
			}
			builder.AddInstruction(
				system.NewCreateAccountInstruction(
					rent,
					mintSize,
					token.ProgramID,
					payer,
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
					payer,
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
	builder := buildInitialTxWithNonceAccount(payer, nonce)

	for _, transfer := range transfers {
		if transfer.SolanaAsset {
			b, err := c.addTransferSolanaAssetInstruction(ctx, builder, transfer, payer, user)
			if err != nil {
				return nil, err
			}
			builder = b
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

func (c *Client) addTransferSolanaAssetInstruction(ctx context.Context, builder *solana.TransactionBuilder, transfer *TokenTransfers, payer, source solana.PublicKey) (*solana.TransactionBuilder, error) {
	if !transfer.SolanaAsset {
		panic(transfer.AssetId)
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

func (c *Client) ExtractTransfersFromTransaction(ctx context.Context, tx *solana.Transaction, meta *rpc.TransactionMeta) ([]*Transfer, error) {
	if meta.Err != nil {
		// Transaction failed, ignore
		return nil, nil
	}

	if err := c.processTransactionWithAddressLookups(ctx, tx); err != nil {
		// FIXME handle address table closed
		if strings.Contains(err.Error(), "get account info: not found") {
			return nil, nil
		}
		return nil, err
	}
	hash := tx.Signatures[0].String()
	msg := tx.Message

	var (
		transfers         = []*Transfer{}
		innerInstructions = map[uint16][]solana.CompiledInstruction{}
		tokenAccounts     = map[solana.PublicKey]token.Account{}
		owners            = []*solana.PublicKey{}
	)

	for _, inner := range meta.InnerInstructions {
		innerInstructions[inner.Index] = inner.Instructions
	}

	for _, balance := range meta.PreTokenBalances {
		if account, err := msg.Account(balance.AccountIndex); err == nil {
			tokenAccounts[account] = token.Account{
				Owner: *balance.Owner,
				Mint:  balance.Mint,
			}
			if !slices.ContainsFunc(owners, func(owner *solana.PublicKey) bool {
				return owner.Equals(*balance.Owner)
			}) {
				owners = append(owners, balance.Owner)
			}
		}
	}

	for index, ix := range msg.Instructions {
		baseIndex := int64(index+1) * 10000
		if transfer := extractTransfersFromInstruction(&msg, ix, tokenAccounts, owners, transfers); transfer != nil {
			transfer.Signature = hash
			transfer.Index = baseIndex
			transfers = append(transfers, transfer)
		}

		for innerIndex, inner := range innerInstructions[uint16(index)] {
			if transfer := extractTransfersFromInstruction(&msg, inner, tokenAccounts, owners, transfers); transfer != nil {
				transfer.Signature = hash
				transfer.Index = baseIndex + int64(innerIndex) + 1
				transfers = append(transfers, transfer)
			}
		}
	}

	return transfers, nil
}
