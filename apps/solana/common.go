package solana

import (
	"fmt"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/util/base58"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
)

const SolanaEmptyAddress = "11111111111111111111111111111111"
const SolanaChainBase = "64692c23-8971-4cf4-84a7-4dd1271dd887"

var SolanaEmptyAddressPublic = solana.MustPublicKeyFromBase58(SolanaEmptyAddress)

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

func BuildSignersGetter(keys ...solana.PrivateKey) func(key solana.PublicKey) *solana.PrivateKey {
	mapKeys := make(map[solana.PublicKey]*solana.PrivateKey)
	for _, k := range keys {
		mapKeys[k.PublicKey()] = &k
	}

	return func(key solana.PublicKey) *solana.PrivateKey {
		return mapKeys[key]
	}
}

func buildInitialTxWithNonceAccount(payer solana.PublicKey, nonce NonceAccount) (*solana.TransactionBuilder, solana.PublicKey) {
	b := solana.NewTransactionBuilder()
	b.SetRecentBlockHash(nonce.Hash)
	b.SetFeePayer(payer)
	b.AddInstruction(system.NewAdvanceNonceAccountInstruction(
		nonce.Address,
		solana.SysVarRecentBlockHashesPubkey,
		payer,
	).Build())
	return b, payer
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

func DecodeTokenTransfer(accounts solana.AccountMetaSlice, data []byte) (*token.TransferChecked, bool) {
	ix, err := token.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}

	if transfer, ok := ix.Impl.(*token.TransferChecked); ok {
		return transfer, true
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
	ix, err := token.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}
	advance, ok := ix.Impl.(*system.AdvanceNonceAccount)
	if ok {
		return advance, true
	}
	return nil, false
}
