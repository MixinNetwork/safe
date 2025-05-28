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
	computebudget "github.com/gagliardetto/solana-go/programs/compute-budget"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/shopspring/decimal"
)

func (c *Client) CreateNonceAccount(ctx context.Context, key, nonce string, rent uint64) (*solana.Transaction, error) {
	payer, err := solana.PrivateKeyFromBase58(key)
	if err != nil {
		panic(err)
	}
	nonceKey, err := solana.PrivateKeyFromBase58(nonce)
	if err != nil {
		panic(err)
	}

	computerPriceIns := c.getPriorityFeeInstruction(ctx)
	block, err := c.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentProcessed)
	if err != nil {
		return nil, fmt.Errorf("solana.GetLatestBlockhash() => %v", err)
	}
	blockhash := block.Value.Blockhash

	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			system.NewCreateAccountInstruction(
				rent,
				NonceAccountSize,
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
			computerPriceIns,
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

func (c *Client) InitializeAccount(ctx context.Context, key, user string) (*solana.Transaction, error) {
	payer, err := solana.PrivateKeyFromBase58(key)
	if err != nil {
		panic(err)
	}
	dst, err := solana.PublicKeyFromBase58(user)
	if err != nil {
		panic(err)
	}

	computerPriceIns := c.getPriorityFeeInstruction(ctx)

	rentExemptBalance, err := c.RPCGetMinimumBalanceForRentExemption(ctx, NormalAccountSize)
	if err != nil {
		return nil, fmt.Errorf("soalan.GetMinimumBalanceForRentExemption(%d) => %v", NormalAccountSize, err)
	}
	block, err := c.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentProcessed)
	if err != nil {
		return nil, fmt.Errorf("solana.GetLatestBlockhash() => %v", err)
	}
	blockhash := block.Value.Blockhash

	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			system.NewTransferInstruction(
				rentExemptBalance,
				payer.PublicKey(),
				dst,
			).Build(),
			computerPriceIns,
		},
		blockhash,
		solana.TransactionPayer(payer.PublicKey()),
	)
	if err != nil {
		panic(err)
	}
	_, err = tx.Sign(BuildSignersGetter(payer))
	if err != nil {
		panic(err)
	}
	return tx, nil
}

func (c *Client) CreateMints(ctx context.Context, payer, mtg solana.PublicKey, assets []*DeployedAsset, rent uint64) (*solana.Transaction, error) {
	builder := solana.NewTransactionBuilder()
	builder.SetFeePayer(payer)

	for _, asset := range assets {
		if asset.ChainId == SolanaChainBase {
			return nil, fmt.Errorf("CreateMints(%s) => invalid asset chain", asset.AssetId)
		}
		mint := solana.MustPublicKeyFromBase58(asset.Address)

		builder.AddInstruction(
			system.NewCreateAccountInstruction(
				rent,
				MintSize,
				token.ProgramID,
				payer,
				mint,
			).Build(),
		)
		builder.AddInstruction(
			token.NewInitializeMint2InstructionBuilder().
				SetDecimals(uint8(asset.Asset.Precision)).
				SetMintAuthority(payer).
				SetMintAccount(solana.MustPublicKeyFromBase58(asset.Address)).Build(),
		)

		pda, _, err := solana.FindTokenMetadataAddress(mint)
		if err != nil {
			return nil, err
		}
		name := asset.Asset.Name
		if len(name) > maxNameLength {
			name = name[:maxNameLength]
		}
		symbol := asset.Asset.Symbol
		if len(symbol) > maxSymbolLength {
			name = name[:maxSymbolLength]
		}
		builder.AddInstruction(
			CustomInstruction{
				Instruction: meta.CreateMetadataAccountV3(meta.CreateMetadataAccountV3Param{
					Metadata:                sc.PublicKeyFromString(pda.String()),
					Mint:                    sc.PublicKeyFromString(mint.String()),
					MintAuthority:           sc.PublicKeyFromString(payer.String()),
					Payer:                   sc.PublicKeyFromString(payer.String()),
					UpdateAuthority:         sc.PublicKeyFromString(mtg.String()),
					UpdateAuthorityIsSigner: false,
					IsMutable:               false,
					Data: meta.DataV2{
						Name:                 name,
						Symbol:               symbol,
						Uri:                  asset.Uri,
						SellerFeeBasisPoints: 0,
					},
				}),
			},
		)

		builder.AddInstruction(
			token.NewSetAuthorityInstruction(token.AuthorityMintTokens, mtg, mint, payer, nil).Build(),
		)
	}

	computerPriceIns := c.getPriorityFeeInstruction(ctx)
	builder.AddInstruction(computerPriceIns)

	block, err := c.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentProcessed)
	if err != nil {
		return nil, fmt.Errorf("solana.GetLatestBlockhash() => %v", err)
	}
	builder.SetRecentBlockHash(block.Value.Blockhash)

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

func (c *Client) TransferOrMintTokens(ctx context.Context, payer, mtg solana.PublicKey, nonce NonceAccount, transfers []*TokenTransfer) (*solana.Transaction, error) {
	builder := c.buildInitialTxWithNonceAccount(ctx, payer, nonce)

	for _, transfer := range transfers {
		if transfer.SolanaAsset {
			b, err := c.addTransferSolanaAssetInstruction(ctx, builder, transfer, payer, mtg)
			if err != nil {
				return nil, err
			}
			builder = b
			continue
		}

		mint := transfer.Mint
		ataAddress := FindAssociatedTokenAddress(transfer.Destination, mint, solana.TokenProgramID)
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

func (c *Client) TransferOrBurnTokens(ctx context.Context, payer, user solana.PublicKey, nonce NonceAccount, transfers []*TokenTransfer) (*solana.Transaction, error) {
	builder := c.buildInitialTxWithNonceAccount(ctx, payer, nonce)

	for _, transfer := range transfers {
		if transfer.SolanaAsset {
			b, err := c.addTransferSolanaAssetInstruction(ctx, builder, transfer, payer, user)
			if err != nil {
				return nil, err
			}
			builder = b
			continue
		}

		ataAddress := FindAssociatedTokenAddress(user, transfer.Mint, solana.TokenProgramID)
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

func (c *Client) addTransferSolanaAssetInstruction(ctx context.Context, builder *solana.TransactionBuilder, transfer *TokenTransfer, payer, source solana.PublicKey) (*solana.TransactionBuilder, error) {
	if !transfer.SolanaAsset {
		panic(transfer.AssetId)
	}
	if transfer.AssetId == transfer.ChainId {
		src := source
		if transfer.Fee {
			src = payer
		}
		builder.AddInstruction(
			system.NewTransferInstruction(
				transfer.Amount,
				src,
				transfer.Destination,
			).Build(),
		)
		return builder, nil
	}

	mintAccount, err := c.RPCGetAccount(ctx, transfer.Mint)
	if err != nil {
		panic(err)
	}
	tokenProgram := mintAccount.Value.Owner

	src := FindAssociatedTokenAddress(source, transfer.Mint, tokenProgram)
	dst := FindAssociatedTokenAddress(transfer.Destination, transfer.Mint, tokenProgram)
	ata, err := c.RPCGetAccount(ctx, dst)
	if err != nil {
		return nil, err
	}

	switch {
	case tokenProgram.Equals(solana.TokenProgramID):
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
	case tokenProgram.Equals(solana.Token2022ProgramID):
		if ata == nil || common.CheckTestEnvironment(ctx) {
			builder.AddInstruction(
				NewAta2022CreateInstruction(
					payer,
					transfer.Destination,
					transfer.Mint,
				).Build(),
			)
		}
		builder.AddInstruction(
			NewToken2022TransferCheckedInstruction(
				transfer.Amount,
				transfer.Decimals,
				src,
				transfer.Mint,
				dst,
				source,
				nil,
			).Build(),
		)
	default:
		panic(fmt.Errorf("invalid token program id: %s", tokenProgram.String()))
	}
	return builder, nil
}

func (c *Client) getPriorityFeeInstruction(ctx context.Context) *computebudget.Instruction {
	if common.CheckTestEnvironment(ctx) {
		return computebudget.NewSetComputeUnitPriceInstruction(0).Build()
	}
	recentFees, err := c.rpcClient.GetRecentPrioritizationFees(ctx, []solana.PublicKey{})
	if err != nil {
		panic(err)
	}
	total := decimal.NewFromInt(0)
	for _, fee := range recentFees {
		total = total.Add(decimal.NewFromUint64(fee.PrioritizationFee))
	}
	fee := total.Div(decimal.NewFromInt(int64(len(recentFees)))).BigInt().Uint64()
	return computebudget.NewSetComputeUnitPriceInstruction(fee).Build()
}

func ExtractTransfersFromTransaction(ctx context.Context, tx *solana.Transaction, meta *rpc.TransactionMeta, exception *solana.PublicKey) ([]*Transfer, error) {
	if meta.Err != nil {
		panic(fmt.Sprint(meta.Err))
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

func GetSignatureIndexOfAccount(tx solana.Transaction, publicKey solana.PublicKey) (int, error) {
	index, err := tx.GetAccountIndex(publicKey)
	if err == nil {
		return int(index), nil
	}
	if strings.Contains(err.Error(), "account not found") {
		return -1, nil
	}
	return -1, err
}
