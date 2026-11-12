package ethereum

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestCheckTransactionPartiallySignedByRejectsWalletRecoveryId(t *testing.T) {
	require := require.New(t)

	key, err := crypto.GenerateKey()
	require.Nil(err)
	holder := hex.EncodeToString(crypto.CompressPubkey(&key.PublicKey))

	tx, err := CreateTransaction(t.Context(), TypeETHTx, 1, "4a4f4e17-4394-42a3-9d84-3cb2e0b34f28",
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
	require.Nil(VerifyMessageSignature(holder, tx.Message, gnosisSig, true))
	require.True(CheckTransactionPartiallySignedBy(raw, holder))
	// A valid signature over a supplied message cannot authenticate changed fields.
	tx.Nonce.SetInt64(1)
	require.False(CheckTransactionPartiallySignedBy(hex.EncodeToString(tx.Marshal()), holder))
	tx.Nonce.SetInt64(0)

	// flipping only the recovery id leaves r and s valid for the holder, but
	// makes Gnosis Safe recover a different owner and revert with GS026
	flippedSig := append([]byte(nil), gnosisSig...)
	if flippedSig[64] == 31 {
		flippedSig[64] = 32
	} else {
		flippedSig[64] = 31
	}
	require.Nil(VerifyMessageSignature(holder, tx.Message, flippedSig, false))
	require.NotNil(VerifyMessageSignature(holder, tx.Message, flippedSig, true))
	tx.Signatures[0] = flippedSig
	raw = hex.EncodeToString(tx.Marshal())
	require.False(CheckTransactionPartiallySignedBy(raw, holder))
}

func TestEnableGuardRejectsInvalidTimelocks(t *testing.T) {
	for _, lock := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 256)} {
		_, err := CreateEnableGuardTransaction(t.Context(), 1, securityTestRequestID, securityTestSafe, securityTestReceiver, lock)
		require.Error(t, err)
	}
}

func TestTransactionConstructorsRejectInvalidAddressesAndChains(t *testing.T) {
	for _, bad := range []string{"", "0x1", "0x" + strings.Repeat("g", 40), "0x" + strings.Repeat("1", 42)} {
		for _, field := range []string{"safe", "destination", "token"} {
			t.Run(field+"/"+bad, func(t *testing.T) {
				safe, receiver, token := securityTestSafe, securityTestReceiver, EthereumEmptyAddress
				switch field {
				case "safe":
					safe = bad
				case "destination":
					receiver = bad
				case "token":
					token = bad
				}
				_, err := CreateTransaction(t.Context(), TypeETHTx, 1, securityTestRequestID, safe, receiver, token, "1", big.NewInt(0))
				require.Error(t, err)
				_, err = CreateMultiSendTransaction(t.Context(), 1, securityTestRequestID, safe,
					[]*Output{{TokenAddress: token, Destination: receiver, Amount: big.NewInt(1)}}, big.NewInt(0))
				require.Error(t, err)
				if field != "token" {
					_, err = CreateEnableGuardTransaction(t.Context(), 1, securityTestRequestID, safe, receiver, big.NewInt(3600))
					require.Error(t, err)
				}
			})
		}
	}
	for _, chain := range []int64{0, -1} {
		_, err := CreateTransaction(t.Context(), TypeETHTx, chain, securityTestRequestID, securityTestSafe, securityTestReceiver, EthereumEmptyAddress, "1", big.NewInt(0))
		require.Error(t, err)
		_, err = CreateMultiSendTransaction(t.Context(), chain, securityTestRequestID, securityTestSafe,
			[]*Output{{TokenAddress: EthereumEmptyAddress, Destination: securityTestReceiver, Amount: big.NewInt(1)}}, big.NewInt(0))
		require.Error(t, err)
		_, err = CreateEnableGuardTransaction(t.Context(), chain, securityTestRequestID, securityTestSafe, securityTestReceiver, big.NewInt(3600))
		require.Error(t, err)
	}
}
