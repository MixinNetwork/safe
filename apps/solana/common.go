package solana

import (
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
)

const SolanaEmptyAddress = "11111111111111111111111111111111"

var SolanaEmptyAddressPublic = solana.MustPublicKeyFromBase58(SolanaEmptyAddress)

type NonceAccount struct {
	Address solana.PublicKey
	Hash    solana.Hash
}

type TokenTransfers struct {
	SolanaAsset bool
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

func buildInitialTxWithNonceAccount(key string, nonce NonceAccount) (*solana.TransactionBuilder, solana.PublicKey) {
	payer := solana.MustPublicKeyFromBase58(key)

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
