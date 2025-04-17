package solana

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"math/big"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/util/base58"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/blocto/solana-go-sdk/types"
	"github.com/gagliardetto/solana-go"
	tokenAta "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gofrs/uuid"
)

const (
	nonceAccountSize  uint64 = 80
	mintSize          uint64 = 82
	NormalAccountSize uint64 = 165

	maxNameLength   = 32
	maxSymbolLength = 10

	SolanaEmptyAddress   = "11111111111111111111111111111111"
	WrappedSolanaAddress = "So11111111111111111111111111111111111111112"
	SolanaChainBase      = "64692c23-8971-4cf4-84a7-4dd1271dd887"
)

type Metadata struct {
	Name        string `json:"name"`
	Symbol      string `json:"symbol"`
	Description string `json:"description"`
	Image       string `json:"image"`
}

type DeployedAsset struct {
	AssetId   string
	ChainId   string
	Address   string
	State     int64
	CreatedAt time.Time

	Uri        string
	Asset      *bot.AssetNetwork
	PrivateKey *solana.PrivateKey
}

type NonceAccount struct {
	Address solana.PublicKey
	Hash    solana.Hash
}

type TokenTransfers struct {
	SolanaAsset bool
	AssetId     string
	ChainId     string
	Mint        solana.PublicKey
	Destination solana.PublicKey
	Amount      uint64
	Decimals    uint8
	Fee         bool
}

type Transfer struct {
	// Signature is the signature of the transaction that contains the transfer.
	Signature string

	// Index is the index of the transfer in the transaction.
	Index int64

	// TokenAddress is the address of the token that is being transferred.
	// If the token is SPL Token, it will be the address of the mint.
	// If the token is native SOL, it will be 'SolanaMintAddress'.
	TokenAddress string

	// AssetId is the mixin version asset id
	AssetId string

	Sender   string
	Receiver string
	Value    *big.Int

	MayClosedWsolAta *solana.PublicKey
}

func FindAssociatedTokenAddress(
	wallet solana.PublicKey,
	mint solana.PublicKey,
	tokenProgramID solana.PublicKey,
) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress([][]byte{
		wallet[:],
		tokenProgramID[:],
		mint[:],
	},
		solana.SPLAssociatedTokenAccountProgramID,
	)
}

func BuildSignersGetter(keys ...solana.PrivateKey) func(key solana.PublicKey) *solana.PrivateKey {
	mapKeys := make(map[solana.PublicKey]*solana.PrivateKey)
	for _, k := range keys {
		mapKeys[k.PublicKey()] = &k
	}

	return func(key solana.PublicKey) *solana.PrivateKey {
		return mapKeys[key]
	}
}

func (c *Client) buildInitialTxWithNonceAccount(ctx context.Context, payer solana.PublicKey, nonce NonceAccount) *solana.TransactionBuilder {
	b := solana.NewTransactionBuilder()
	b.SetRecentBlockHash(nonce.Hash)
	b.SetFeePayer(payer)
	b.AddInstruction(system.NewAdvanceNonceAccountInstruction(
		nonce.Address,
		solana.SysVarRecentBlockHashesPubkey,
		payer,
	).Build())

	computerPriceIns := c.getPriorityFeeInstruction(ctx)
	b.AddInstruction(computerPriceIns)
	return b
}

func (a *DeployedAsset) PublicKey() solana.PublicKey {
	return solana.MustPublicKeyFromBase58(a.Address)
}

func PrivateKeyFromSeed(seed []byte) solana.PrivateKey {
	return solana.PrivateKey(ed25519.NewKeyFromSeed(seed[:])[:])
}

func PublicKeyFromEd25519Public(pub string) solana.PublicKey {
	return solana.PublicKeyFromBytes(common.DecodeHexOrPanic(pub))
}

func VerifyAssetKey(assetKey string) error {
	if assetKey == SolanaEmptyAddress {
		return nil
	}
	pub := base58.Decode(assetKey)
	if len(pub) != 32 {
		return fmt.Errorf("invalid solana assetKey length %s", assetKey)
	}
	var k crypto.Key
	copy(k[:], pub)
	if !k.CheckKey() {
		return fmt.Errorf("invalid solana assetKey public key %s", assetKey)
	}
	addr := base58.Encode(pub)
	if addr != assetKey {
		return fmt.Errorf("invalid solana assetKey %s", assetKey)
	}
	return nil
}

func GenerateKeyForExternalAsset(members []string, threshold int, assetId string) solana.PrivateKey {
	id := fmt.Sprintf("MEMBERS:%v:%d", members, threshold)
	id = common.UniqueId(id, assetId)
	seed := crypto.Sha256Hash(uuid.Must(uuid.FromString(id)).Bytes())
	key := PrivateKeyFromSeed(seed[:])
	return key
}

func GenerateAssetId(assetKey string) string {
	if assetKey == SolanaEmptyAddress {
		return common.SafeSolanaChainId
	}
	err := VerifyAssetKey(assetKey)
	if err != nil {
		panic(assetKey)
	}

	return ethereum.BuildChainAssetId(SolanaChainBase, assetKey)
}

func ExtractBurnsFromTransaction(ctx context.Context, tx *solana.Transaction) []*token.BurnChecked {
	var bs []*token.BurnChecked
	msg := tx.Message
	for _, cix := range msg.Instructions {
		programKey, err := msg.Program(cix.ProgramIDIndex)
		if err != nil {
			panic(err)
		}
		switch programKey {
		case solana.TokenProgramID, solana.Token2022ProgramID:
		default:
			continue
		}

		accounts, err := cix.ResolveInstructionAccounts(&msg)
		if err != nil {
			panic(err)
		}
		burn, ok := DecodeTokenBurn(accounts, cix.Data)
		if !ok {
			continue
		}
		bs = append(bs, burn)
	}

	return bs
}

func ExtractCreatedAtasFromTransaction(ctx context.Context, tx *solana.Transaction) []solana.PublicKey {
	var as []solana.PublicKey
	msg := tx.Message

	for _, cix := range msg.Instructions {
		programKey, err := msg.Program(cix.ProgramIDIndex)
		if err != nil {
			panic(err)
		}
		if programKey != tokenAta.ProgramID {
			continue
		}
		accounts, err := cix.ResolveInstructionAccounts(&msg)
		if err != nil {
			panic(err)
		}
		ix, err := tokenAta.DecodeInstruction(accounts, cix.Data)
		if err != nil {
			panic(err)
		}
		if a, ok := ix.Impl.(*tokenAta.Create); ok {
			ata := a.GetAccounts()[1]
			as = append(as, ata.PublicKey)
		}
		if a, ok := ix.Impl.(*Create); ok {
			ata := a.GetAccounts()[1]
			as = append(as, ata.PublicKey)
		}
	}

	return as
}

func DecodeSystemTransfer(accounts solana.AccountMetaSlice, data []byte) (*system.Transfer, bool) {
	ix, err := system.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}

	if transfer, ok := ix.Impl.(*system.Transfer); ok {
		return transfer, true
	}

	if transferWithSeed, ok := ix.Impl.(*system.TransferWithSeed); ok {
		t := system.NewTransferInstructionBuilder()
		t.SetFundingAccount(transferWithSeed.GetFundingAccount().PublicKey)
		t.SetRecipientAccount(transferWithSeed.GetRecipientAccount().PublicKey)
		t.SetLamports(*transferWithSeed.Lamports)
		return t, true
	}

	return nil, false
}

func DecodeTokenTransferChecked(accounts solana.AccountMetaSlice, data []byte) (*token.TransferChecked, bool) {
	ix, err := token.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}

	if transfer, ok := ix.Impl.(*token.TransferChecked); ok {
		return transfer, true
	}
	return nil, false
}

func decodeTokenTransfer(accounts solana.AccountMetaSlice, data []byte) (*token.Transfer, bool) {
	ix, err := token.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}

	if transfer, ok := ix.Impl.(*token.Transfer); ok {
		return transfer, true
	}

	if transferChecked, ok := ix.Impl.(*token.TransferChecked); ok {
		t := token.NewTransferInstructionBuilder()
		t.SetSourceAccount(transferChecked.GetSourceAccount().PublicKey)
		t.SetDestinationAccount(transferChecked.GetDestinationAccount().PublicKey)
		t.SetAmount(*transferChecked.Amount)
		return t, true
	}

	return nil, false
}

func decodeCloseAccount(accounts solana.AccountMetaSlice, data []byte) (*token.CloseAccount, bool) {
	ix, err := token.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}

	close, ok := ix.Impl.(*token.CloseAccount)
	return close, ok
}

func decodeTokenInitializeAccount(accounts solana.AccountMetaSlice, data []byte) (*token.InitializeAccount, bool) {
	ix, err := token.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}

	if init, ok := ix.Impl.(*token.InitializeAccount); ok {
		return init, true
	}

	if init, ok := ix.Impl.(*token.InitializeAccount2); ok {
		i := token.NewInitializeAccountInstructionBuilder()
		i.SetAccount(init.GetAccount().PublicKey)
		i.SetMintAccount(init.GetMintAccount().PublicKey)
		i.SetOwnerAccount(*init.Owner)
		return i, true
	}

	if init, ok := ix.Impl.(*token.InitializeAccount3); ok {
		i := token.NewInitializeAccountInstructionBuilder()
		i.SetAccount(init.GetAccount().PublicKey)
		i.SetMintAccount(init.GetMintAccount().PublicKey)
		i.SetOwnerAccount(*init.Owner)
		return i, true
	}

	return nil, false
}

func DecodeTokenBurn(accounts solana.AccountMetaSlice, data []byte) (*token.BurnChecked, bool) {
	ix, err := token.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}

	if burn, ok := ix.Impl.(*token.BurnChecked); ok {
		return burn, true
	}
	return nil, false
}

func DecodeCreateAccount(accounts solana.AccountMetaSlice, data []byte) (*system.CreateAccount, bool) {
	ix, err := system.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}
	mint, ok := ix.Impl.(*system.CreateAccount)
	if ok {
		return mint, true
	}
	return nil, false
}

func DecodeMintToken(accounts solana.AccountMetaSlice, data []byte) (*token.InitializeMint2, bool) {
	ix, err := token.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}
	mint, ok := ix.Impl.(*token.InitializeMint2)
	if ok {
		return mint, true
	}
	return nil, false
}

func DecodeTokenMintTo(accounts solana.AccountMetaSlice, data []byte) (*token.MintTo, bool) {
	ix, err := token.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}
	mintTo, ok := ix.Impl.(*token.MintTo)
	if ok {
		return mintTo, true
	}
	return nil, false
}

func DecodeNonceAdvance(accounts solana.AccountMetaSlice, data []byte) (*system.AdvanceNonceAccount, error) {
	ix, err := system.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, err
	}
	advance, ok := ix.Impl.(*system.AdvanceNonceAccount)
	if ok {
		return advance, nil
	}
	return nil, fmt.Errorf("invalid nonce advance instruction")
}

func NonceAccountFromTx(tx *solana.Transaction) (*system.AdvanceNonceAccount, error) {
	ins := tx.Message.Instructions[0]
	accounts, err := ins.ResolveInstructionAccounts(&tx.Message)
	if err != nil {
		return nil, err
	}
	return DecodeNonceAdvance(accounts, ins.Data)
}

func extractTransfersFromInstruction(
	msg *solana.Message,
	cix solana.CompiledInstruction,
	tokenAccounts map[solana.PublicKey]token.Account,
	owners []*solana.PublicKey,
	transfers []*Transfer,
) *Transfer {
	programKey, err := msg.Program(cix.ProgramIDIndex)
	if err != nil {
		panic(err)
	}

	accounts, err := cix.ResolveInstructionAccounts(msg)
	if err != nil {
		panic(err)
	}

	switch programKey {
	case system.ProgramID:
		if transfer, ok := DecodeSystemTransfer(accounts, cix.Data); ok {
			return &Transfer{
				TokenAddress: SolanaEmptyAddress,
				AssetId:      SolanaChainBase,
				Sender:       transfer.GetFundingAccount().PublicKey.String(),
				Receiver:     transfer.GetRecipientAccount().PublicKey.String(),
				Value:        new(big.Int).SetUint64(*transfer.Lamports),
			}
		}
	case solana.TokenProgramID, solana.Token2022ProgramID:
		// account to receiver token may not be ata
		if init, ok := decodeTokenInitializeAccount(accounts, cix.Data); ok {
			tokenAccounts[init.GetAccount().PublicKey] = token.Account{
				Owner: init.GetOwnerAccount().PublicKey,
				Mint:  init.GetMintAccount().PublicKey,
			}
		}

		if transfer, ok := decodeTokenTransfer(accounts, cix.Data); ok {
			from, ok := tokenAccounts[transfer.GetSourceAccount().PublicKey]
			if !ok {
				panic(fmt.Sprintf("source token account not found: %s", transfer.GetSourceAccount().PublicKey.String()))
			}

			to, ok := tokenAccounts[transfer.GetDestinationAccount().PublicKey]
			if !ok {
				if from.Mint.String() == WrappedSolanaAddress {
					for _, owner := range owners {
						ata, _, err := FindAssociatedTokenAddress(*owner, from.Mint, programKey)
						if err != nil {
							panic(err)
						}
						if ata.Equals(transfer.GetDestinationAccount().PublicKey) {
							return &Transfer{
								TokenAddress:     from.Mint.String(),
								AssetId:          ethereum.BuildChainAssetId(SolanaChainBase, from.Mint.String()),
								Sender:           from.Owner.String(),
								Receiver:         owner.String(),
								Value:            new(big.Int).SetUint64(*transfer.Amount),
								MayClosedWsolAta: &ata,
							}
						}
					}
				}
				panic(fmt.Sprintf("destination token account not found: %s", transfer.GetDestinationAccount().PublicKey.String()))
			}

			return &Transfer{
				TokenAddress: from.Mint.String(),
				AssetId:      ethereum.BuildChainAssetId(SolanaChainBase, from.Mint.String()),
				Sender:       from.Owner.String(),
				Receiver:     to.Owner.String(),
				Value:        new(big.Int).SetUint64(*transfer.Amount),
			}
		}

		// check WSOL transfer and WSOL token account closed
		if close, ok := decodeCloseAccount(accounts, cix.Data); ok {
			closed := close.GetAccount().PublicKey
			if owner, ok := tokenAccounts[closed]; ok {
				for index, transfer := range transfers {
					if !solana.MustPublicKeyFromBase58(transfer.Receiver).Equals(owner.Owner) || transfer.TokenAddress != WrappedSolanaAddress {
						continue
					}
					transfers[index].TokenAddress = SolanaEmptyAddress
					transfers[index].AssetId = SolanaChainBase
					transfers[index].MayClosedWsolAta = nil
				}
				return nil
			}

			for index, transfer := range transfers {
				if transfer.MayClosedWsolAta == nil || !transfer.MayClosedWsolAta.Equals(closed) {
					continue
				}
				transfers[index].TokenAddress = SolanaEmptyAddress
				transfers[index].AssetId = SolanaChainBase
				transfers[index].MayClosedWsolAta = nil
			}
		}
	}

	return nil
}

type CustomInstruction struct {
	Instruction types.Instruction
}

func (cs CustomInstruction) ProgramID() solana.PublicKey {
	return solana.MustPublicKeyFromBase58(cs.Instruction.ProgramID.String())
}

func (cs CustomInstruction) Accounts() []*solana.AccountMeta {
	var as []*solana.AccountMeta
	for _, a := range cs.Instruction.Accounts {
		as = append(as, &solana.AccountMeta{
			PublicKey:  solana.MustPublicKeyFromBase58(a.PubKey.String()),
			IsWritable: a.IsWritable,
			IsSigner:   a.IsSigner,
		})
	}
	return as
}

func (cs CustomInstruction) Data() ([]byte, error) {
	return cs.Instruction.Data, nil
}
