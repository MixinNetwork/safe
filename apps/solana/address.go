package solana

import (
	"encoding/binary"

	"github.com/MixinNetwork/safe/apps/solana/squads_mpl"
	solana "github.com/gagliardetto/solana-go"
)

const (
	DefaultAuthorityIndex uint32 = 1
)

func GetAuthorityPDA(ms solana.PublicKey, index uint32) solana.PublicKey {
	indexBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBytes, index)

	address, _, err := solana.FindProgramAddress(
		[][]byte{
			[]byte("squad"),
			ms.Bytes(),
			indexBytes,
			[]byte("authority"),
		},
		squads_mpl.ProgramID,
	)
	if err != nil {
		panic(err)
	}
	return address
}

func GetDefaultAuthorityPDA(ms solana.PublicKey) solana.PublicKey {
	return GetAuthorityPDA(ms, DefaultAuthorityIndex)
}

func GetMultisigPDA(createKey solana.PublicKey) solana.PublicKey {
	address, _, err := solana.FindProgramAddress(
		[][]byte{
			[]byte("squad"),
			createKey.Bytes(),
			[]byte("multisig"),
		},
		squads_mpl.ProgramID,
	)
	if err != nil {
		panic(err)
	}
	return address
}

func GetTransactionPDA(ms solana.PublicKey, nonce uint32) solana.PublicKey {
	nonceBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(nonceBytes, nonce)

	address, _, err := solana.FindProgramAddress(
		[][]byte{
			[]byte("squad"),
			ms.Bytes(),
			nonceBytes,
			[]byte("transaction"),
		},
		squads_mpl.ProgramID,
	)
	if err != nil {
		panic(err)
	}
	return address
}

func GetInstructionPDA(txPda solana.PublicKey, index uint8) solana.PublicKey {
	address, _, err := solana.FindProgramAddress(
		[][]byte{
			[]byte("squad"),
			txPda.Bytes(),
			{index},
			[]byte("instruction"),
		},
		squads_mpl.ProgramID,
	)
	if err != nil {
		panic(err)
	}
	return address
}
