package solana

import (
	"context"
	"fmt"
	"math/big"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/util/base58"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
)

const (
	SolanaEmptyAddress = "11111111111111111111111111111111"
	SolanaChainBase    = "64692c23-8971-4cf4-84a7-4dd1271dd887"
)

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

func buildInitialTxWithNonceAccount(payer solana.PublicKey, nonce NonceAccount) *solana.TransactionBuilder {
	b := solana.NewTransactionBuilder()
	b.SetRecentBlockHash(nonce.Hash)
	b.SetFeePayer(payer)
	b.AddInstruction(system.NewAdvanceNonceAccountInstruction(
		nonce.Address,
		solana.SysVarRecentBlockHashesPubkey,
		payer,
	).Build())
	return b
}

func PublicKeyFromEd25519Public(pub string) solana.PublicKey {
	return solana.PublicKeyFromBytes(common.DecodeHexOrPanic(pub))
}

func VerifyAssetKey(assetKey string) error {
	if assetKey == "11111111111111111111111111111111" {
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

func GenerateAssetId(assetKey string) string {
	if assetKey == "11111111111111111111111111111111" {
		return common.SafeSolanaChainId
	}
	err := VerifyAssetKey(assetKey)
	if err != nil {
		panic(assetKey)
	}

	return ethereum.BuildChainAssetId(SolanaChainBase, assetKey)
}

func ExtractTransfersFromTransaction(ctx context.Context, tx *solana.Transaction, meta *rpc.TransactionMeta) []*Transfer {
	if meta.Err != nil {
		// Transaction failed, ignore
		return nil
	}

	hash := tx.Signatures[0].String()
	msg := tx.Message

	var (
		transfers         = []*Transfer{}
		innerInstructions = map[uint16][]solana.CompiledInstruction{}
		tokenAccounts     = map[solana.PublicKey]token.Account{}
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
		}
	}

	for index, ix := range msg.Instructions {
		baseIndex := int64(index+1) * 10000
		if transfer := extractTransfersFromInstruction(&msg, ix, tokenAccounts); transfer != nil {
			transfer.Signature = hash
			transfer.Index = baseIndex
			transfers = append(transfers, transfer)
		}

		for innerIndex, inner := range innerInstructions[uint16(index)] {
			if transfer := extractTransfersFromInstruction(&msg, inner, tokenAccounts); transfer != nil {
				transfer.Signature = hash
				transfer.Index = baseIndex + int64(innerIndex) + 1
				transfers = append(transfers, transfer)
			}
		}
	}

	return transfers
}

func ExtractBurnsFromTransaction(ctx context.Context, tx *solana.Transaction) []*token.BurnChecked {
	var bs []*token.BurnChecked
	msg := tx.Message
	for _, cix := range msg.Instructions {
		programKey, err := msg.Program(cix.ProgramIDIndex)
		if err != nil {
			panic(err)
		}
		if programKey != token.ProgramID {
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

func DecodeTokenMint(accounts solana.AccountMetaSlice, data []byte) (*token.MintTo, bool) {
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

func DecodeNonceAdvance(accounts solana.AccountMetaSlice, data []byte) (*system.AdvanceNonceAccount, bool) {
	ix, err := system.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}
	advance, ok := ix.Impl.(*system.AdvanceNonceAccount)
	if ok {
		return advance, true
	}
	return nil, false
}

func extractTransfersFromInstruction(msg *solana.Message, cix solana.CompiledInstruction, tokenAccounts map[solana.PublicKey]token.Account) *Transfer {
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
		if transfer, ok := decodeTokenTransfer(accounts, cix.Data); ok {
			from, ok := tokenAccounts[transfer.GetSourceAccount().PublicKey]
			if !ok {
				panic(fmt.Sprintf("token account not found: %s", transfer.GetSourceAccount().PublicKey.String()))
			}

			to, ok := tokenAccounts[transfer.GetDestinationAccount().PublicKey]
			if !ok {
				panic(fmt.Sprintf("token account not found: %s", transfer.GetDestinationAccount().PublicKey.String()))
			}

			return &Transfer{
				TokenAddress: from.Mint.String(),
				AssetId:      ethereum.BuildChainAssetId(SolanaChainBase, from.Mint.String()),
				Sender:       from.Owner.String(),
				Receiver:     to.Owner.String(),
				Value:        new(big.Int).SetUint64(*transfer.Amount),
			}
		}
	}

	return nil
}
