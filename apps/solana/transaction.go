package solana

import (
	"context"
	"fmt"
	"math/big"

	"github.com/MixinNetwork/safe/apps/solana/squads_mpl"
	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	ata "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	token "github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	confirm "github.com/gagliardetto/solana-go/rpc/sendAndConfirmTransaction"
)

type Output struct {
	TokenAddress string   `json:"token_address"`
	Destination  string   `json:"destination"`
	Amount       *big.Int `json:"amount"`
}

func ExtractOutputs(tx *solana.Transaction) []*Output {
	var (
		outputs       []*Output
		tokenAccounts = make(map[solana.PublicKey]token.Account)
	)

	for _, ix := range tx.Message.Instructions {
		programID, err := tx.Message.Program(ix.ProgramIDIndex)
		if err != nil {
			panic(err)
		}

		accounts, err := ix.ResolveInstructionAccounts(&tx.Message)
		if err != nil {
			panic(err)
		}

		if programID == ata.ProgramID {
			// inst must be createIdempotent
			if len(ix.Data) == 0 || ix.Data[0] != 1 {
				panic(fmt.Sprintf("ata: invalid createIdempotent instruction: %+v", ix))
			}

			inst, err := ata.DecodeInstruction(accounts, ix.Data)
			if err != nil {
				panic(err)
			}

			create, ok := inst.Impl.(*ata.Create)
			if !ok {
				panic(fmt.Sprintf("ata: invalid create instruction: %+v", inst))
			}

			tokenAccounts[create.AccountMetaSlice[1].PublicKey] = token.Account{
				Mint:  create.Mint,
				Owner: create.Wallet,
			}

			continue
		}

		if programID != squads_mpl.ProgramID {
			continue
		}

		inst, err := squads_mpl.DecodeInstruction(accounts, ix.Data)
		if err != nil {
			panic(err)
		}

		addInst, ok := inst.Impl.(*squads_mpl.AddInstruction)
		if !ok {
			continue
		}

		multisigAccount := addInst.GetMultisigAccount()
		authority := GetDefaultAuthorityPDA(multisigAccount.PublicKey)

		// clear accounts
		accounts = make(solana.AccountMetaSlice, len(addInst.IncomingInstruction.Keys))
		for i, key := range addInst.IncomingInstruction.Keys {
			accounts[i] = &solana.AccountMeta{
				PublicKey:  key.Pubkey,
				IsWritable: key.IsWritable,
				IsSigner:   key.IsSigner,
			}
		}

		switch addInst.IncomingInstruction.ProgramId {
		case system.ProgramID:
			inst, err := system.DecodeInstruction(accounts, addInst.IncomingInstruction.Data)
			if err != nil {
				panic(err)
			}

			transfer, ok := inst.Impl.(*system.Transfer)
			if !ok {
				panic(fmt.Sprintf("system: invalid transfer instruction: %+v", inst))
			}

			if transfer.GetFundingAccount().PublicKey != authority {
				panic(fmt.Sprintf("system: invalid transfer instruction: %+v", inst))
			}

			outputs = append(outputs, &Output{
				TokenAddress: SolanaEmptyAddress,
				Destination:  transfer.GetRecipientAccount().PublicKey.String(),
				Amount:       new(big.Int).SetUint64(*transfer.Lamports),
			})
		case token.ProgramID:
			inst, err := token.DecodeInstruction(accounts, addInst.IncomingInstruction.Data)
			if err != nil {
				panic(err)
			}

			transfer, ok := inst.Impl.(*token.Transfer)
			if !ok {
				panic(fmt.Sprintf("token: invalid transfer instruction: %+v", inst))
			}

			destination, ok := tokenAccounts[transfer.GetDestinationAccount().PublicKey]
			if !ok {
				panic(fmt.Sprintf("token: invalid transfer instruction: %+v", inst))
			}

			// validate source account
			if from, _, _ := solana.FindAssociatedTokenAddress(authority, destination.Mint); from != transfer.GetSourceAccount().PublicKey {
				panic(fmt.Sprintf("token: invalid transfer instruction: %+v", inst))
			}

			outputs = append(outputs, &Output{
				TokenAddress: destination.Mint.String(),
				Destination:  destination.Owner.String(),
				Amount:       new(big.Int).SetUint64(*transfer.Amount),
			})
		}
	}

	return outputs
}

func (c *Client) BuildSquadsSafe(ctx context.Context, holder, signer, observer solana.PublicKey, payer solana.PrivateKey) (*squads_mpl.Ms, *solana.Transaction, error) {
	ms := &squads_mpl.Ms{
		Threshold: 2,
		CreateKey: holder,
		Keys:      []solana.PublicKey{holder, signer, observer},
	}

	inst := squads_mpl.NewCreateInstruction(
		2,
		holder,
		ms.Keys,
		"",
		GetMultisigPDA(holder),
		holder,
		system.ProgramID,
	).Build()

	tx, err := c.useNonceAccountAsBlockhash(ctx, []solana.Instruction{inst}, payer)
	if err != nil {
		return nil, nil, fmt.Errorf("solana.useNonceAccountAsBlockhash() => %v", err)
	}

	// 这个阶段的 tx 只缺少 holder 的签名
	return ms, tx, nil
}

const nonceAccountSize uint64 = 80

func (c *Client) useNonceAccountAsBlockhash(ctx context.Context, instructions []solana.Instruction, payer solana.PrivateKey) (*solana.Transaction, error) {
	nonceKey := solana.NewWallet()
	nonceAccount, err := c.createNonceAccount(ctx, nonceKey.PrivateKey, payer)
	if err != nil {
		return nil, fmt.Errorf("solana.createNonceAccount() => %v", err)
	}

	var nonceAccountData system.NonceAccount
	if err := bin.NewBinDecoder(nonceAccount.Data.GetBinary()).Decode(&nonceAccountData); err != nil {
		return nil, fmt.Errorf("solana.NewBinDecoder() => %v", err)
	}

	b := solana.NewTransactionBuilder()
	b.SetRecentBlockHash(solana.Hash(nonceAccountData.Nonce))
	b.SetFeePayer(payer.PublicKey())

	// advance nonce account
	b.AddInstruction(system.NewAdvanceNonceAccountInstruction(
		nonceKey.PublicKey(),
		solana.SysVarRecentBlockHashesPubkey,
		payer.PublicKey(),
	).Build())

	for _, inst := range instructions {
		b.AddInstruction(inst)
	}

	// withdraw nonce account
	b.AddInstruction(system.NewWithdrawNonceAccountInstruction(
		nonceAccount.Lamports,
		nonceKey.PublicKey(),
		payer.PublicKey(),
		solana.SysVarRecentBlockHashesPubkey,
		solana.SysVarRentPubkey,
		payer.PublicKey(),
	).Build())

	tx, err := b.Build()
	if err != nil {
		panic(err)
	}

	if _, err := tx.PartialSign(buildSignersGetter(payer)); err != nil {
		panic(err)
	}

	return tx, nil
}

func (c *Client) createNonceAccount(ctx context.Context, nonceKey, payer solana.PrivateKey) (*rpc.Account, error) {
	client := c.getRPCClient()
	blockhash, err := client.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("solana.GetLatestBlockhash() => %v", err)
	}

	// 计算 Nonce Account 所需的最小 lamports
	// system.NonceAccountSize = 80 bytes
	rentExemptBalance, err := client.GetMinimumBalanceForRentExemption(
		ctx,
		nonceAccountSize,
		rpc.CommitmentFinalized,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get rent exempt balance: %w", err)
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
		blockhash.Value.Blockhash,
		solana.TransactionPayer(payer.PublicKey()),
	)

	if err != nil {
		panic(err)
	}

	if _, err := tx.Sign(buildSignersGetter(nonceKey, payer)); err != nil {
		panic(err)
	}

	ws, err := c.connectWs(ctx)
	if err != nil {
		return nil, fmt.Errorf("solana.connectWs() => %v", err)
	}

	defer ws.Close()

	if _, err := confirm.SendAndConfirmTransaction(ctx, client, ws, tx); err != nil {
		return nil, fmt.Errorf("solana.SendAndConfirmTransaction() => %v", err)
	}

	result, err := client.GetAccountInfo(ctx, nonceKey.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("solana.GetAccountInfo() => %v", err)
	}

	return result.Value, nil
}

func buildSignersGetter(keys ...solana.PrivateKey) func(key solana.PublicKey) *solana.PrivateKey {
	mapKeys := make(map[solana.PublicKey]*solana.PrivateKey)
	for _, k := range keys {
		mapKeys[k.PublicKey()] = &k
	}

	return func(key solana.PublicKey) *solana.PrivateKey {
		return mapKeys[key]
	}
}
