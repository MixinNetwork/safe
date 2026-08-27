package ethereum

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestValidateGnosisRecovery(t *testing.T) {
	require := require.New(t)

	sig := make([]byte, 65)

	// standard eth_sign recovery ids accepted by the Gnosis Safe contract
	sig[64] = 31
	require.Nil(ValidateGnosisRecovery(sig))
	sig[64] = 32
	require.Nil(ValidateGnosisRecovery(sig))

	// standard wallet recovery ids revert on chain with GS026
	sig[64] = 27
	require.NotNil(ValidateGnosisRecovery(sig))
	sig[64] = 28
	require.NotNil(ValidateGnosisRecovery(sig))

	// raw recovery ids revert on chain as well
	sig[64] = 0
	require.NotNil(ValidateGnosisRecovery(sig))
	sig[64] = 1
	require.NotNil(ValidateGnosisRecovery(sig))

	// anything else is invalid
	sig[64] = 30
	require.NotNil(ValidateGnosisRecovery(sig))
	sig[64] = 33
	require.NotNil(ValidateGnosisRecovery(sig))
	sig[64] = 255
	require.NotNil(ValidateGnosisRecovery(sig))

	// invalid length
	require.NotNil(ValidateGnosisRecovery(sig[:64]))
	require.NotNil(ValidateGnosisRecovery(nil))
}

func TestCheckTransactionPartiallySignedByRejectsWalletRecoveryId(t *testing.T) {
	require := require.New(t)

	key, err := crypto.GenerateKey()
	require.Nil(err)
	holder := hex.EncodeToString(crypto.CompressPubkey(&key.PublicKey))

	tx, err := CreateTransaction(context.Background(), TypeETHTx, 1, "4a4f4e17-4394-42a3-9d84-3cb2e0b34f28",
		"0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222",
		EthereumEmptyAddress, "1000000000000000000", big.NewInt(0))
	require.Nil(err)

	hash := HashMessageForSignature(hex.EncodeToString(tx.Message))
	sig, err := crypto.Sign(hash, key)
	require.Nil(err)
	require.True(sig[64] < 2)

	// a signature produced by a standard wallet, v = 27/28: it verifies
	// off chain without the recovery check, but must be rejected with it
	// because it reverts on chain
	walletSig := append([]byte(nil), sig...)
	walletSig[64] += 27
	tx.Signatures[0] = walletSig
	require.Nil(VerifyMessageSignature(holder, tx.Message, walletSig, false))
	require.NotNil(VerifyMessageSignature(holder, tx.Message, walletSig, true))
	raw := hex.EncodeToString(tx.Marshal())
	require.False(CheckTransactionPartiallySignedBy(raw, holder))

	// the same signature in the eth_sign format, v = 31/32, is accepted
	gnosisSig := append([]byte(nil), sig...)
	gnosisSig[64] += 31
	tx.Signatures[0] = gnosisSig
	raw = hex.EncodeToString(tx.Marshal())
	require.True(CheckTransactionPartiallySignedBy(raw, holder))
}
