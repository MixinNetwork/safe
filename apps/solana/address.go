package solana

import (
	"encoding/binary"

	"github.com/MixinNetwork/safe/apps/solana/squads_mpl"
	solana "github.com/gagliardetto/solana-go"
)

const (
	DefaultAuthorityIndex = 1
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
