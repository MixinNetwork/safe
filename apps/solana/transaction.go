package solana

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"slices"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/safe/apps/solana/squads_mpl"
	solana "github.com/gagliardetto/solana-go"
	ata "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	token "github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	confirm "github.com/gagliardetto/solana-go/rpc/sendAndConfirmTransaction"
	"github.com/gofrs/uuid/v5"
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

type BuildSquadsSafeParams struct {
	Members   []solana.PublicKey
	Creator   solana.PublicKey
	Nonce     solana.PublicKey
	BlockHash solana.Hash
	Payer     solana.PublicKey
	Threshold uint16
}

func BuildSquadsSafe(params BuildSquadsSafeParams) *solana.Transaction {
	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			system.NewAdvanceNonceAccountInstruction(
				params.Nonce,
				solana.SysVarRecentBlockHashesPubkey,
				params.Payer,
			).Build(),
			squads_mpl.NewCreateInstruction(
				params.Threshold,
				params.Creator,
				params.Members,
				"",
				GetMultisigPDA(params.Creator),
				params.Creator,
				system.ProgramID,
			).Build(),
		},
		params.BlockHash,
		solana.TransactionPayer(params.Payer),
	)
	if err != nil {
		panic(fmt.Errorf("solana.NewTransaction() => %v", err))
	}

	return tx
}

type TransactionRequest struct {
	Flag         uint8
	RequestID    uuid.UUID
	NonceAccount solana.PublicKey
	BlockHash    solana.Hash
	PayerAccount solana.PublicKey

	// extra is the extra data for the transaction
	// 1. transaction reference to a storage transaction
	// 2. destination address
	Extra [32]byte
}

func DecodeTransactionRequest(b []byte) (*TransactionRequest, error) {
	var (
		dec = common.NewDecoder(b)
		req TransactionRequest
	)

	if b, err := dec.ReadByte(); err != nil {
		return nil, err
	} else {
		req.Flag = b
	}

	if err := dec.Read(req.RequestID[:]); err != nil {
		return nil, err
	}

	if err := dec.Read(req.NonceAccount[:]); err != nil {
		return nil, err
	}

	if err := dec.Read(req.BlockHash[:]); err != nil {
		return nil, err
	}

	if err := dec.Read(req.PayerAccount[:]); err != nil {
		return nil, err
	}

	if err := dec.Read(req.Extra[:]); err != nil {
		return nil, err
	}

	// it should be io.EOF
	if _, err := dec.ReadByte(); err != io.EOF {
		return nil, fmt.Errorf("invalid transaction request length")
	}

	return &req, nil
}

// CreateTransactionFromOutputs creates a transaction from outputs
// `creator` is the creator of the multisig & the transaction, used to be the holder of the safe
func CreateTransactionFromOutputs(req *TransactionRequest, outputs []*Output, voters []solana.PublicKey, creator solana.PublicKey, nonce uint32) (*solana.Transaction, error) {
	instructions := []solana.Instruction{
		system.NewAdvanceNonceAccountInstruction(
			req.NonceAccount,
			solana.SysVarRecentBlockHashesPubkey,
			req.PayerAccount,
		).Build(),
	}

	msPda := GetMultisigPDA(creator)
	authorityPad := GetDefaultAuthorityPDA(msPda)
	txPda := GetTransactionPDA(msPda, nonce)

	// 1. create transaction
	instructions = append(instructions, squads_mpl.NewCreateTransactionInstruction(
		DefaultAuthorityIndex,
		msPda,
		txPda,
		creator,
		system.ProgramID,
	).Build())

	// 2. add transfer instructions
	var (
		innerInstructions []solana.Instruction
		tokenAccounts     = make(map[solana.PublicKey]struct{})
	)

	for _, output := range outputs {
		// native solana
		if output.TokenAddress == SolanaEmptyAddress {
			innerInstructions = append(innerInstructions, system.NewTransferInstruction(
				output.Amount.Uint64(),
				authorityPad,
				solana.MPK(output.Destination),
			).Build())

			continue
		}

		mint := solana.MPK(output.TokenAddress)
		source, _, err := solana.FindAssociatedTokenAddress(authorityPad, mint)
		if err != nil {
			return nil, fmt.Errorf("solana.FindAssociatedTokenAddress() => %v", err)
		}

		destination, _, err := solana.FindAssociatedTokenAddress(solana.MPK(output.Destination), mint)
		if err != nil {
			return nil, fmt.Errorf("solana.FindAssociatedTokenAddress() => %v", err)
		}

		innerInstructions = append(innerInstructions, token.NewTransferInstruction(
			output.Amount.Uint64(),
			source,
			destination,
			authorityPad,
			nil,
		).Build())

		if _, ok := tokenAccounts[destination]; !ok {
			inst := ata.NewCreateInstruction(req.PayerAccount, solana.MPK(output.Destination), mint).Build()
			// createIdempotent
			instructions = append(instructions, solana.NewInstruction(inst.ProgramID(), inst.Accounts(), []byte{1}))
			tokenAccounts[destination] = struct{}{}
		}
	}

	var ixKeysList solana.AccountMetaSlice

	for idx, inner := range innerInstructions {
		if idx > 255 {
			return nil, fmt.Errorf("too many instructions")
		}

		data, err := inner.Data()
		if err != nil {
			return nil, fmt.Errorf("solana.Instruction.Data() => %v", err)
		}

		ixKey := GetInstructionPDA(txPda, uint8(idx+1))
		ixKeysList.Append(solana.Meta(ixKey))
		ixKeysList.Append(solana.Meta(inner.ProgramID()))

		var keys []squads_mpl.MsAccountMeta
		for _, account := range inner.Accounts() {
			keys = append(keys, squads_mpl.MsAccountMeta{
				Pubkey:     account.PublicKey,
				IsSigner:   account.IsSigner,
				IsWritable: account.IsWritable,
			})

			ixKeysList.Append(account)
		}

		instructions = append(instructions, squads_mpl.NewAddInstructionInstruction(
			squads_mpl.IncomingInstruction{
				ProgramId: inner.ProgramID(),
				Keys:      keys,
				Data:      data,
			},
			msPda,
			txPda,
			ixKey,
			creator,
			system.ProgramID,
		).Build())
	}

	// active transaction
	instructions = append(instructions, squads_mpl.NewActivateTransactionInstruction(
		msPda,
		txPda,
		creator,
	).Build())

	// vote
	for _, voter := range voters {
		instructions = append(instructions, squads_mpl.NewApproveTransactionInstruction(
			msPda,
			txPda,
			voter,
		).Build())
	}

	var (
		keysUnique  solana.AccountMetaSlice
		keyIndexMap = make([]byte, len(ixKeysList))
	)

	for idx, key := range ixKeysList {
		p := slices.IndexFunc(keysUnique, func(k *solana.AccountMeta) bool {
			return k.PublicKey.Equals(key.PublicKey) && k.IsWritable == key.IsWritable
		})

		if p < 0 {
			keysUnique.Append(key)
			p = len(keysUnique) - 1
		}

		if p > 255 {
			return nil, fmt.Errorf("too many unique keys")
		}

		keyIndexMap[idx] = byte(p)
	}

	// execute
	executeIxBuilder := squads_mpl.NewExecuteTransactionInstruction(keyIndexMap, msPda, txPda, creator)
	for _, key := range keysUnique {
		executeIxBuilder.Append(key)
	}

	instructions = append(instructions, executeIxBuilder.Build())
	return solana.NewTransaction(instructions, req.BlockHash, solana.TransactionPayer(req.PayerAccount))
}

const nonceAccountSize uint64 = 80

func (c *Client) ReadNonceAccount(ctx context.Context, nonceKey solana.PublicKey) (*system.NonceAccount, error) {
	client := c.getRPCClient()
	var account system.NonceAccount
	if err := client.GetAccountDataInto(ctx, nonceKey, &account); err != nil {
		return nil, fmt.Errorf("solana.GetAccountInfo() => %v", err)
	}
	return &account, nil
}

func (c *Client) CreateNonceAccount(ctx context.Context, nonceKey, payer solana.PrivateKey) (*system.NonceAccount, error) {
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

	if err := Sign(tx, nonceKey, payer); err != nil {
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

	return c.ReadNonceAccount(ctx, nonceKey.PublicKey())
}

func Sign(tx *solana.Transaction, keys ...solana.PrivateKey) error {
	mapKeys := make(map[solana.PublicKey]*solana.PrivateKey)
	for _, k := range keys {
		mapKeys[k.PublicKey()] = &k
	}

	_, err := tx.PartialSign(func(key solana.PublicKey) *solana.PrivateKey {
		return mapKeys[key]
	})
	return err
}

// AddSignature add new signature to the transaction
func AddSignature(tx *solana.Transaction, pub solana.PublicKey, signature solana.Signature) error {
	content, err := tx.Message.MarshalBinary()
	if err != nil {
		return fmt.Errorf("solana.Transaction.Message.MarshalBinary() => %v", err)
	}

	if !pub.Verify(content, signature) {
		return fmt.Errorf("signature verification failed")
	}

	numRequiredSignatures := int(tx.Message.Header.NumRequiredSignatures)
	if len(tx.Signatures) == 0 {
		tx.Signatures = make([]solana.Signature, numRequiredSignatures)
	} else if len(tx.Signatures) != numRequiredSignatures {
		return fmt.Errorf("invalid signatures length, expected %d, actual %d", numRequiredSignatures, len(tx.Signatures))
	}

	idx := slices.Index(tx.Message.AccountKeys, pub)
	if idx < 0 || idx >= numRequiredSignatures {
		return fmt.Errorf("signature index out of range")
	}

	tx.Signatures[idx] = signature
	return nil
}

func GetAuthorityAddressFromCreateTx(tx *solana.Transaction) solana.PublicKey {
	for _, ix := range tx.Message.Instructions {
		program, _ := tx.Message.Program(ix.ProgramIDIndex)
		if program != squads_mpl.ProgramID {
			continue
		}

		accounts, err := ix.ResolveInstructionAccounts(&tx.Message)
		if err != nil {
			continue
		}

		inst, err := squads_mpl.DecodeInstruction(accounts, ix.Data)
		if err != nil {
			continue
		}

		create, ok := inst.Impl.(*squads_mpl.Create)
		if !ok {
			continue
		}

		return GetDefaultAuthorityPDA(create.GetMultisigAccount().PublicKey)
	}

	return solana.PublicKey{}
}

func CheckTransactionSignedBy(tx *solana.Transaction, pub solana.PublicKey) bool {
	content, err := tx.Message.MarshalBinary()
	if err != nil {
		panic(err)
	}

	for _, sig := range tx.Signatures {
		if pub.Verify(content, sig) {
			return true
		}
	}

	return false
}
