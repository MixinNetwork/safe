package solana

import (
	"errors"
	"fmt"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	tokenAta "github.com/gagliardetto/solana-go/programs/associated-token-account"
	format "github.com/gagliardetto/solana-go/text/format"
	treeout "github.com/gagliardetto/treeout"
)

type Create struct {
	Payer  solana.PublicKey `bin:"-" borsh_skip:"true"`
	Wallet solana.PublicKey `bin:"-" borsh_skip:"true"`
	Mint   solana.PublicKey `bin:"-" borsh_skip:"true"`

	// [0] = [WRITE, SIGNER] Payer
	// ··········· Funding account
	//
	// [1] = [WRITE] AssociatedTokenAccount
	// ··········· Associated token account address to be created
	//
	// [2] = [] Wallet
	// ··········· Wallet address for the new associated token account
	//
	// [3] = [] TokenMint
	// ··········· The token mint for the new associated token account
	//
	// [4] = [] SystemProgram
	// ··········· System program ID
	//
	// [5] = [] TokenProgram
	// ··········· SPL token program ID
	//
	// [6] = [] SysVarRent
	// ··········· SysVarRentPubkey
	solana.AccountMetaSlice `bin:"-" borsh_skip:"true"`
}

// NewCreateInstructionBuilder creates a new `Create` instruction builder.
func NewCreateInstructionBuilder() *Create {
	nd := &Create{}
	return nd
}

func (inst *Create) SetPayer(payer solana.PublicKey) *Create {
	inst.Payer = payer
	return inst
}

func (inst *Create) SetWallet(wallet solana.PublicKey) *Create {
	inst.Wallet = wallet
	return inst
}

func (inst *Create) SetMint(mint solana.PublicKey) *Create {
	inst.Mint = mint
	return inst
}

func (inst Create) Build() *tokenAta.Instruction {

	// Find the associatedTokenAddress;
	associatedTokenAddress, _, _ := FindAssociatedTokenAddress(
		inst.Wallet,
		inst.Mint,
		solana.Token2022ProgramID,
	)

	keys := []*solana.AccountMeta{
		{
			PublicKey:  inst.Payer,
			IsSigner:   true,
			IsWritable: true,
		},
		{
			PublicKey:  associatedTokenAddress,
			IsSigner:   false,
			IsWritable: true,
		},
		{
			PublicKey:  inst.Wallet,
			IsSigner:   false,
			IsWritable: false,
		},
		{
			PublicKey:  inst.Mint,
			IsSigner:   false,
			IsWritable: false,
		},
		{
			PublicKey:  solana.SystemProgramID,
			IsSigner:   false,
			IsWritable: false,
		},
		{
			PublicKey:  solana.Token2022ProgramID, // origin: solana.TokenProgramID
			IsSigner:   false,
			IsWritable: false,
		},
		{
			PublicKey:  solana.SysVarRentPubkey,
			IsSigner:   false,
			IsWritable: false,
		},
	}

	inst.AccountMetaSlice = keys

	return &tokenAta.Instruction{BaseVariant: bin.BaseVariant{
		Impl:   inst,
		TypeID: bin.NoTypeIDDefaultID,
	}}
}

// ValidateAndBuild validates the instruction accounts.
// If there is a validation error, return the error.
// Otherwise, build and return the instruction.
func (inst Create) ValidateAndBuild() (*tokenAta.Instruction, error) {
	if err := inst.Validate(); err != nil {
		return nil, err
	}
	return inst.Build(), nil
}

func (inst *Create) Validate() error {
	if inst.Payer.IsZero() {
		return errors.New("payer not set")
	}
	if inst.Wallet.IsZero() {
		return errors.New("wallet not set")
	}
	if inst.Mint.IsZero() {
		return errors.New("mint not set")
	}
	_, _, err := FindAssociatedTokenAddress(
		inst.Wallet,
		inst.Mint,
		solana.Token2022ProgramID,
	)
	if err != nil {
		return fmt.Errorf("error while FindAssociatedTokenAddress: %w", err)
	}
	return nil
}

func (inst *Create) EncodeToTree(parent treeout.Branches) {
	parent.Child(format.Program(tokenAta.ProgramName, tokenAta.ProgramID)).
		//
		ParentFunc(func(programBranch treeout.Branches) {
			programBranch.Child(format.Instruction("Create")).
				//
				ParentFunc(func(instructionBranch treeout.Branches) {

					// Parameters of the instruction:
					instructionBranch.Child("Params[len=0]").ParentFunc(func(paramsBranch treeout.Branches) {})

					// Accounts of the instruction:
					instructionBranch.Child("Accounts[len=7").ParentFunc(func(accountsBranch treeout.Branches) {
						accountsBranch.Child(format.Meta("                 payer", inst.AccountMetaSlice.Get(0)))
						accountsBranch.Child(format.Meta("associatedTokenAddress", inst.AccountMetaSlice.Get(1)))
						accountsBranch.Child(format.Meta("                wallet", inst.AccountMetaSlice.Get(2)))
						accountsBranch.Child(format.Meta("             tokenMint", inst.AccountMetaSlice.Get(3)))
						accountsBranch.Child(format.Meta("         systemProgram", inst.AccountMetaSlice.Get(4)))
						accountsBranch.Child(format.Meta("          tokenProgram", inst.AccountMetaSlice.Get(5)))
						accountsBranch.Child(format.Meta("            sysVarRent", inst.AccountMetaSlice.Get(6)))
					})
				})
		})
}

func (inst Create) MarshalWithEncoder(encoder *bin.Encoder) error {
	return encoder.WriteBytes([]byte{}, false)
}

func (inst *Create) UnmarshalWithDecoder(decoder *bin.Decoder) error {
	return nil
}

func NewAta2022CreateInstruction(
	payer solana.PublicKey,
	walletAddress solana.PublicKey,
	splTokenMintAddress solana.PublicKey,
) *Create {
	return NewCreateInstructionBuilder().
		SetPayer(payer).
		SetWallet(walletAddress).
		SetMint(splTokenMintAddress)
}
