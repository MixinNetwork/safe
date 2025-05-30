package solana

import (
	"bytes"
	"errors"
	"fmt"

	ag_spew "github.com/davecgh/go-spew/spew"
	ag_binary "github.com/gagliardetto/binary"
	ag_solanago "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/token"
	ag_text "github.com/gagliardetto/solana-go/text"
	ag_format "github.com/gagliardetto/solana-go/text/format"
	ag_treeout "github.com/gagliardetto/treeout"
)

const MAX_SIGNERS = 11
const ProgramName = "Token 2022"

type Instruction struct {
	ag_binary.BaseVariant
}

var InstructionImplDef = ag_binary.NewVariantDefinition(
	ag_binary.Uint8TypeIDEncoding,
	[]ag_binary.VariantType{
		{
			Name: "TransferChecked", Type: (*TransferChecked)(nil),
		},
	},
)

func (inst *Instruction) ProgramID() ag_solanago.PublicKey {
	return ag_solanago.Token2022ProgramID
}

func (inst *Instruction) Accounts() (out []*ag_solanago.AccountMeta) {
	return inst.Impl.(ag_solanago.AccountsGettable).GetAccounts()
}

func (inst *Instruction) Data() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := ag_binary.NewBinEncoder(buf).Encode(inst); err != nil {
		return nil, fmt.Errorf("unable to encode instruction: %w", err)
	}
	return buf.Bytes(), nil
}

func (inst *Instruction) EncodeToTree(parent ag_treeout.Branches) {
	if enToTree, ok := inst.Impl.(ag_text.EncodableToTree); ok {
		enToTree.EncodeToTree(parent)
	} else {
		parent.Child(ag_spew.Sdump(inst))
	}
}

func (inst *Instruction) TextEncode(encoder *ag_text.Encoder, option *ag_text.Option) error {
	return encoder.Encode(inst.Impl, option)
}

func (inst *Instruction) UnmarshalWithDecoder(decoder *ag_binary.Decoder) error {
	return inst.BaseVariant.UnmarshalBinaryVariant(decoder, InstructionImplDef)
}

func (inst Instruction) MarshalWithEncoder(encoder *ag_binary.Encoder) error {
	err := encoder.WriteUint8(inst.TypeID.Uint8())
	if err != nil {
		return fmt.Errorf("unable to write variant type: %w", err)
	}
	return encoder.Encode(inst.Impl)
}

func registryDecodeInstruction(accounts []*ag_solanago.AccountMeta, data []byte) (any, error) {
	inst, err := DecodeInstruction(accounts, data)
	if err != nil {
		return nil, err
	}
	return inst, nil
}

func DecodeInstruction(accounts []*ag_solanago.AccountMeta, data []byte) (*Instruction, error) {
	inst := new(Instruction)
	if err := ag_binary.NewBinDecoder(data).Decode(inst); err != nil {
		return nil, fmt.Errorf("unable to decode instruction: %w", err)
	}
	if v, ok := inst.Impl.(ag_solanago.AccountsSettable); ok {
		err := v.SetAccounts(accounts)
		if err != nil {
			return nil, fmt.Errorf("unable to set accounts for instruction: %w", err)
		}
	}
	return inst, nil
}

// Transfers tokens from one account to another either directly or via a
// delegate.  If this account is associated with the native mint then equal
// amounts of SOL and Tokens will be transferred to the destination
// account.
//
// This instruction differs from Transfer in that the token mint and
// decimals value is checked by the caller.  This may be useful when
// creating transactions offline or within a hardware wallet.
type TransferChecked struct {
	// The amount of tokens to transfer.
	Amount *uint64

	// Expected number of base 10 digits to the right of the decimal place.
	Decimals *uint8

	// [0] = [WRITE] source
	// ··········· The source account.
	//
	// [1] = [] mint
	// ··········· The token mint.
	//
	// [2] = [WRITE] destination
	// ··········· The destination account.
	//
	// [3] = [] owner
	// ··········· The source account's owner/delegate.
	//
	// [4...] = [SIGNER] signers
	// ··········· M signer accounts.
	Accounts ag_solanago.AccountMetaSlice `bin:"-" borsh_skip:"true"`
	Signers  ag_solanago.AccountMetaSlice `bin:"-" borsh_skip:"true"`
}

func (obj *TransferChecked) SetAccounts(accounts []*ag_solanago.AccountMeta) error {
	obj.Accounts, obj.Signers = ag_solanago.AccountMetaSlice(accounts).SplitFrom(4)
	return nil
}

func (slice TransferChecked) GetAccounts() (accounts []*ag_solanago.AccountMeta) {
	accounts = append(accounts, slice.Accounts...)
	accounts = append(accounts, slice.Signers...)
	return
}

// NewTransferCheckedInstructionBuilder creates a new `TransferChecked` instruction builder.
func NewTransferCheckedInstructionBuilder() *TransferChecked {
	nd := &TransferChecked{
		Accounts: make(ag_solanago.AccountMetaSlice, 4),
		Signers:  make(ag_solanago.AccountMetaSlice, 0),
	}
	return nd
}

// SetAmount sets the "amount" parameter.
// The amount of tokens to transfer.
func (inst *TransferChecked) SetAmount(amount uint64) *TransferChecked {
	inst.Amount = &amount
	return inst
}

// SetDecimals sets the "decimals" parameter.
// Expected number of base 10 digits to the right of the decimal place.
func (inst *TransferChecked) SetDecimals(decimals uint8) *TransferChecked {
	inst.Decimals = &decimals
	return inst
}

// SetSourceAccount sets the "source" account.
// The source account.
func (inst *TransferChecked) SetSourceAccount(source ag_solanago.PublicKey) *TransferChecked {
	inst.Accounts[0] = ag_solanago.Meta(source).WRITE()
	return inst
}

// GetSourceAccount gets the "source" account.
// The source account.
func (inst *TransferChecked) GetSourceAccount() *ag_solanago.AccountMeta {
	return inst.Accounts[0]
}

// SetMintAccount sets the "mint" account.
// The token mint.
func (inst *TransferChecked) SetMintAccount(mint ag_solanago.PublicKey) *TransferChecked {
	inst.Accounts[1] = ag_solanago.Meta(mint)
	return inst
}

// GetMintAccount gets the "mint" account.
// The token mint.
func (inst *TransferChecked) GetMintAccount() *ag_solanago.AccountMeta {
	return inst.Accounts[1]
}

// SetDestinationAccount sets the "destination" account.
// The destination account.
func (inst *TransferChecked) SetDestinationAccount(destination ag_solanago.PublicKey) *TransferChecked {
	inst.Accounts[2] = ag_solanago.Meta(destination).WRITE()
	return inst
}

// GetDestinationAccount gets the "destination" account.
// The destination account.
func (inst *TransferChecked) GetDestinationAccount() *ag_solanago.AccountMeta {
	return inst.Accounts[2]
}

// SetOwnerAccount sets the "owner" account.
// The source account's owner/delegate.
func (inst *TransferChecked) SetOwnerAccount(owner ag_solanago.PublicKey, multisigSigners ...ag_solanago.PublicKey) *TransferChecked {
	inst.Accounts[3] = ag_solanago.Meta(owner)
	if len(multisigSigners) == 0 {
		inst.Accounts[3].SIGNER()
	}
	for _, signer := range multisigSigners {
		inst.Signers = append(inst.Signers, ag_solanago.Meta(signer).SIGNER())
	}
	return inst
}

// GetOwnerAccount gets the "owner" account.
// The source account's owner/delegate.
func (inst *TransferChecked) GetOwnerAccount() *ag_solanago.AccountMeta {
	return inst.Accounts[3]
}

func (inst TransferChecked) Build() *Instruction {
	return &Instruction{BaseVariant: ag_binary.BaseVariant{
		Impl:   inst,
		TypeID: ag_binary.TypeIDFromUint8(token.Instruction_TransferChecked),
	}}
}

// ValidateAndBuild validates the instruction parameters and accounts;
// if there is a validation error, it returns the error.
// Otherwise, it builds and returns the instruction.
func (inst TransferChecked) ValidateAndBuild() (*Instruction, error) {
	if err := inst.Validate(); err != nil {
		return nil, err
	}
	return inst.Build(), nil
}

func (inst *TransferChecked) Validate() error {
	// Check whether all (required) parameters are set:
	{
		if inst.Amount == nil {
			return errors.New("amount parameter is not set")
		}
		if inst.Decimals == nil {
			return errors.New("decimals parameter is not set")
		}
	}

	// Check whether all (required) accounts are set:
	{
		if inst.Accounts[0] == nil {
			return errors.New("accounts.Source is not set")
		}
		if inst.Accounts[1] == nil {
			return errors.New("accounts.Mint is not set")
		}
		if inst.Accounts[2] == nil {
			return errors.New("accounts.Destination is not set")
		}
		if inst.Accounts[3] == nil {
			return errors.New("accounts.Owner is not set")
		}
		if !inst.Accounts[3].IsSigner && len(inst.Signers) == 0 {
			return fmt.Errorf("accounts.Signers is not set")
		}
		if len(inst.Signers) > MAX_SIGNERS {
			return fmt.Errorf("too many signers; got %v, but max is 11", len(inst.Signers))
		}
	}
	return nil
}

func (inst *TransferChecked) EncodeToTree(parent ag_treeout.Branches) {
	parent.Child(ag_format.Program(ProgramName, ag_solanago.Token2022ProgramID)).
		//
		ParentFunc(func(programBranch ag_treeout.Branches) {
			programBranch.Child(ag_format.Instruction("TransferChecked")).
				//
				ParentFunc(func(instructionBranch ag_treeout.Branches) {

					// Parameters of the instruction:
					instructionBranch.Child("Params").ParentFunc(func(paramsBranch ag_treeout.Branches) {
						paramsBranch.Child(ag_format.Param("  Amount", *inst.Amount))
						paramsBranch.Child(ag_format.Param("Decimals", *inst.Decimals))
					})

					// Accounts of the instruction:
					instructionBranch.Child("Accounts").ParentFunc(func(accountsBranch ag_treeout.Branches) {
						accountsBranch.Child(ag_format.Meta("     source", inst.Accounts[0]))
						accountsBranch.Child(ag_format.Meta("       mint", inst.Accounts[1]))
						accountsBranch.Child(ag_format.Meta("destination", inst.Accounts[2]))
						accountsBranch.Child(ag_format.Meta("      owner", inst.Accounts[3]))

						signersBranch := accountsBranch.Child(fmt.Sprintf("signers[len=%v]", len(inst.Signers)))
						for i, v := range inst.Signers {
							if len(inst.Signers) > 9 && i < 10 {
								signersBranch.Child(ag_format.Meta(fmt.Sprintf(" [%v]", i), v))
							} else {
								signersBranch.Child(ag_format.Meta(fmt.Sprintf("[%v]", i), v))
							}
						}
					})
				})
		})
}

func (obj TransferChecked) MarshalWithEncoder(encoder *ag_binary.Encoder) (err error) {
	// Serialize `Amount` param:
	err = encoder.Encode(obj.Amount)
	if err != nil {
		return err
	}
	// Serialize `Decimals` param:
	err = encoder.Encode(obj.Decimals)
	if err != nil {
		return err
	}
	return nil
}
func (obj *TransferChecked) UnmarshalWithDecoder(decoder *ag_binary.Decoder) (err error) {
	// Deserialize `Amount`:
	err = decoder.Decode(&obj.Amount)
	if err != nil {
		return err
	}
	// Deserialize `Decimals`:
	err = decoder.Decode(&obj.Decimals)
	if err != nil {
		return err
	}
	return nil
}

// NewTransferCheckedInstruction declares a new TransferChecked instruction with the provided parameters and accounts.
func NewToken2022TransferCheckedInstruction(
	// Parameters:
	amount uint64,
	decimals uint8,
	// Accounts:
	source ag_solanago.PublicKey,
	mint ag_solanago.PublicKey,
	destination ag_solanago.PublicKey,
	owner ag_solanago.PublicKey,
	multisigSigners []ag_solanago.PublicKey,
) *TransferChecked {
	return NewTransferCheckedInstructionBuilder().
		SetAmount(amount).
		SetDecimals(decimals).
		SetSourceAccount(source).
		SetMintAccount(mint).
		SetDestinationAccount(destination).
		SetOwnerAccount(owner, multisigSigners...)
}

func init() {
	ag_solanago.RegisterInstructionDecoder(ag_solanago.Token2022ProgramID, registryDecodeInstruction)
}
