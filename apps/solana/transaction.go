package solana

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/MixinNetwork/safe/common"
	sc "github.com/blocto/solana-go-sdk/common"
	meta "github.com/blocto/solana-go-sdk/program/metaplex/token_metadata"
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

func (c *Client) CreateMints(ctx context.Context, payer, mtg solana.PublicKey, nonce NonceAccount, assets []*DeployedAsset) (*solana.Transaction, error) {
	client := c.getRPCClient()
	builder := buildInitialTxWithNonceAccount(payer, nonce)

	rent, err := client.GetMinimumBalanceForRentExemption(ctx, mintSize, rpc.CommitmentConfirmed)
	if err != nil {
		return nil, fmt.Errorf("soalan.GetMinimumBalanceForRentExemption() => %v", err)
	}
	for _, asset := range assets {
		if asset.Asset.ChainID == SolanaChainBase {
			return nil, fmt.Errorf("CreateMints(%s) => invalid asset chain", asset.AssetId)
		}
		mint := solana.MustPublicKeyFromBase58(asset.Address)
		builder.AddInstruction(
			system.NewCreateAccountInstruction(
				rent,
				mintSize,
				token.ProgramID,
				payer,
				mint,
			).Build(),
		)
		initMint := token.NewInitializeMint2InstructionBuilder().
			SetDecimals(uint8(asset.Asset.Precision)).
			SetMintAuthority(mtg).
			SetMintAccount(solana.MustPublicKeyFromBase58(asset.Address)).Build()
		builder.AddInstruction(initMint)
		pda, _, err := solana.FindTokenMetadataAddress(mint)
		if err != nil {
			return nil, err
		}
		builder.AddInstruction(
			CustomInstruction{
				Instruction: meta.CreateMetadataAccountV3(meta.CreateMetadataAccountV3Param{
					Metadata:                sc.PublicKeyFromString(pda.String()),
					Mint:                    sc.PublicKeyFromString(mint.String()),
					MintAuthority:           sc.PublicKeyFromString(mtg.String()),
					Payer:                   sc.PublicKeyFromString(payer.String()),
					UpdateAuthority:         sc.PublicKeyFromString(mtg.String()),
					UpdateAuthorityIsSigner: true,
					IsMutable:               false,
					Data: meta.DataV2{
						Name:                 fmt.Sprintf("%s (Mixin)", asset.Asset.Name),
						Symbol:               asset.Asset.Symbol,
						Uri:                  asset.Uri,
						SellerFeeBasisPoints: 0,
					},
				}),
			},
		)
	}

	tx, err := builder.Build()
	if err != nil {
		panic(err)
	}
	for _, asset := range assets {
		if asset.PrivateKey == nil {
			return nil, fmt.Errorf("CreateMints(%s) => asset private key is required", asset.AssetId)
		}
		_, err = tx.PartialSign(BuildSignersGetter(*asset.PrivateKey))
		if err != nil {
			if common.CheckTestEnvironment(ctx) {
				tx.Signatures[1] = solana.MustSignatureFromBase58("449h9tg5hCHigegVuH6Waoh8ACDYc5hrhZh2t9td2ToFgtBHrkzH7Z2vSE2nnmNdksUkj71k7eaQhdHrRgj19b5W")
				continue
			}
			panic(err)
		}
	}
	return tx, nil
}

func (c *Client) TransferOrMintTokens(ctx context.Context, payer, mtg solana.PublicKey, nonce NonceAccount, transfers []TokenTransfers) (*solana.Transaction, error) {
	builder := buildInitialTxWithNonceAccount(payer, nonce)

	for _, transfer := range transfers {
		if transfer.SolanaAsset {
			b, err := c.addTransferSolanaAssetInstruction(ctx, builder, &transfer, payer, mtg)
			if err != nil {
				return nil, err
			}
			builder = b
			continue
		}

		mint := transfer.Mint
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

	mintAccount, err := c.RPCGetAccount(ctx, transfer.Mint)
	if err != nil {
		panic(err)
	}
	isToken2022 := false
	if mintAccount.Value.Owner.Equals(solana.Token2022ProgramID) {
		isToken2022 = true
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
		ins := tokenAta.NewCreateInstruction(
			payer,
			transfer.Destination,
			transfer.Mint,
		).Build()
		if isToken2022 {
			ins = NewAta2022CreateInstruction(
				payer,
				transfer.Destination,
				transfer.Mint,
			).Build()
		}
		builder.AddInstruction(ins)
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

func (c *Client) ExtractTransfersFromTransaction(ctx context.Context, tx *solana.Transaction, meta *rpc.TransactionMeta, exception *solana.PublicKey) ([]*Transfer, error) {
	if meta.Err != nil {
		// Transaction failed, ignore
		return nil, nil
	}

	if err := c.ProcessTransactionWithAddressLookups(ctx, tx); err != nil {
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
			if exception != nil && exception.String() == transfer.Receiver {
				continue
			}
			transfer.Signature = hash
			transfer.Index = baseIndex
			transfers = append(transfers, transfer)
		}

		for innerIndex, inner := range innerInstructions[uint16(index)] {
			if transfer := extractTransfersFromInstruction(&msg, inner, tokenAccounts, owners, transfers); transfer != nil {
				if exception != nil && exception.String() == transfer.Receiver {
					continue
				}
				transfer.Signature = hash
				transfer.Index = baseIndex + int64(innerIndex) + 1
				transfers = append(transfers, transfer)
			}
		}
	}

	return transfers, nil
}

func ExtractMintsFromTransaction(tx *solana.Transaction) []string {
	var assets []string
	for index, ix := range tx.Message.Instructions {
		if index == 0 {
			continue
		}
		programKey, err := tx.Message.Program(ix.ProgramIDIndex)
		if err != nil {
			panic(err)
		}
		accounts, err := ix.ResolveInstructionAccounts(&tx.Message)
		if err != nil {
			panic(err)
		}

		switch programKey {
		case solana.TokenProgramID, solana.Token2022ProgramID:
			if mint, ok := DecodeMintToken(accounts, ix.Data); ok {
				address := mint.GetMintAccount().PublicKey
				assets = append(assets, address.String())
				continue
			}
		}
	}
	return assets
}
