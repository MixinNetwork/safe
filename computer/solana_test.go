package computer

import (
	"context"
	"testing"

	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/require"
)

const (
	testRpcEndpoint         = ""
	testWsEndpoint          = ""
	testNonceAccountAddress = "FLq1XqAbaFjib59q6mRDRFEzoQnTShWu1Vis7q57HKtd"
	testNonceAccountHash    = "8j6J9Z8GdbkY1VsJKuKk799nGfkNchMGZ9LY2bdvtYrZ"

	testMtgPrivKey      = "5q5XTS2ehNJAUsGMbR1g5VHfBtkVfeprptwbX4mYkrrZDtf5SAYGsbxaFg9wkmt3iWRBS5qpBcfYZuWH6Z11C2eP"
	testPayerPrivKey    = "56HtVW5YQ9Xi8MTeQFAWdSuzV17mrDAr1AUCYzTdx36VLvsodA89eSuZd6axrufzo4tyoUNdgjDpm4fnLJLRcXmF"
	testRecentBlockHash = "Er4JTcKx3ahtWxvYcyLF3XJBv4fhoK2Sn3vP1tCEqP8M"
	testRent            = 1447680

	testUserPrivKey = "5sZ5EeUhZ1wkHvdDgHGa2fySDzFjDXLhD9dtUCme4mEVp7Pzy6q53oZynXWbnhjtRjR6FQFuaBXyqF5gJt41bpQb"
	testMintPrivKey = "4yJWKkTnXGvVUS5Ds2sDZAYnbE4bTvzRkJcY2Kmvw4xQWRi8VsBpbWj7C1qfas92saa9CrjuWFfTDChCnV2dB6pd"

	testUserNonceAccountPrivKey = "5mCExzNoFSY8UwVbGYPiVtmfeWtqoNeprRymq4wU7yZwWxVCrpXoX7F2KSEFrbVEPRSUjejAeNBbFYMhC3iiu4F5"
	testUserNonceAccountHash1   = "H1awZsQvgqwDEcwSLUiMdJuJ82Y2i4Lbre8phFfJ993g"
)

func TestComputerSolana(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	rpcClient := solanaApp.NewClient(testRpcEndpoint, testWsEndpoint)

	nonceAccount := solana.MustPrivateKeyFromBase58(testUserNonceAccountPrivKey)
	require.Equal("DaJw3pa9rxr25AT1HnQnmPvwS4JbnwNvQbNLm8PJRhqV", nonceAccount.PublicKey().String())
	tx, err := rpcClient.CreateNonceAccount(ctx, testPayerPrivKey, testUserNonceAccountPrivKey, testRecentBlockHash, testRent)
	require.Nil(err)
	require.Equal(
		"AgADBc3FbI0IejAbIRRLKrXhKGtQpdlB7gL2JIjbAwi5Q9LWutSveZUmRL2AiBs5NLPieK0vTu6jYU4cQoNQ2QXqxOwGp9UXGSxWjuCKhF9z0peIzwNcMUWyGrNE2AYuqUAAAAan1RcZLFxRIYzJTD1K8X9Y2u4Im6H9ROPb2YoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNuR9FjPwGu+S4a32Om0ek4RfWX/36aP3NnMqbME/YsgIEAgABNAAAAAAAFxYAAAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAwECAyQGAAAAzcVsjQh6MBshFEsqteEoa1Cl2UHuAvYkiNsDCLlD0tY=",
		tx.Message.ToBase64(),
	)
	require.Len(tx.Signatures, 2)
	require.Equal("kHqMbpJrdjv7XmY6Fz2upNWXGBdaxVgHFFL9fyHKnM6KACFkZAMghTRNxBickceCoQsWzxFECe7NgWeFeLdrpV6", tx.Signatures[0].String())
	require.Equal("2wBzjnftUvKV4mWMt6AzHRfWCiCQ6arYp6QS2mjSWrvN6cMsp3oCeo2Y4y3V1SJQj7Fn481ovhZrJayD3cgd3qRc", tx.Signatures[1].String())

	mint := solana.MustPrivateKeyFromBase58(testMintPrivKey)
	require.Equal("7k3LQatQh4pFSLhemgdyK4JKX8nyiQoKjFh7ZEqD4jvD", mint.PublicKey().String())
	user := solana.MustPrivateKeyFromBase58(testUserPrivKey)
	require.Equal("4jGVQSJrCfgLNSvTfwTLejm88bUXppqwvBzFZADtsY2F", user.PublicKey().String())
	mtg := solana.MustPrivateKeyFromBase58(testMtgPrivKey)
	require.Equal("A9YZ4M9MTerux6yP27RC72yNAFewoyRu3V8JJDqCdRf9", mtg.PublicKey().String())
	payer := solana.MustPrivateKeyFromBase58(testPayerPrivKey)
	require.Equal("ErFBVPGYmi8Vjuf1jAfmZLzyFHLnF9c1MNhfcEQGdgMb", payer.PublicKey().String())

	nonce := solanaApp.NonceAccount{
		Hash:    solana.MustHashFromBase58(testUserNonceAccountHash1),
		Address: nonceAccount.PublicKey(),
	}
	transfers := []solanaApp.TokenTransfers{
		{
			IsSol:       true,
			Amount:      10000000,
			Destination: user.PublicKey(),
		},
		{
			Mint:        mint,
			Amount:      10000000,
			Destination: user.PublicKey(),
			Decimals:    8,
		},
	}
	tx, err = rpcClient.TransferTokens(ctx, testPayerPrivKey, testMtgPrivKey, nonce, transfers)
	require.Nil(err)
	require.Equal(
		"AwAFC83FbI0IejAbIRRLKrXhKGtQpdlB7gL2JIjbAwi5Q9LWh+mBbeScWnn/TP5dr0xFz7V2EwYACKukUWzjrDD6k9RkLLxwGoFACZKqiUySwUhPyCGVNzc8O4yjc3M7XUcMbrrUr3mVJkS9gIgbOTSz4nitL07uo2FOHEKDUNkF6sTsN2b4E5F03p01h6e5Eo461IsTij6ElObZW4qVdaayYWQJxEz9jCArEmdI/aeLBT2ByII/+LALSw2bXMmDOWEsHAan1RcZLFaO4IqEX3PSl4jPA1wxRbIas0TYBi6pQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG3fbh12Whk9nL4UbO63msHLSF7V9bN5E6jPWFfv8AqQan1RcZLFxRIYzJTD1K8X9Y2u4Im6H9ROPb2YoAAAAAjJclj04kifG7PRApFI4NgwtaE5na/xCEBI572Nvp+Fnt4V4o90OzKUDLSaoj1tCx8aTOnuRwGYtkr4MfIunrSwYHAwMGAAQEAAAABwIBBAwCAAAAgJaYAAAAAAAHAgACNAAAAABgTRYAAAAAAFIAAAAAAAAABt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKkIAQJDFAiH6YFt5Jxaef9M/l2vTEXPtXYTBgAIq6RRbOOsMPqT1AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoHAAUEAgcICQAIAwIFAQkHgJaYAAAAAAA=",
		tx.Message.ToBase64(),
	)
}

func TestGetNonceAccountHash(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	rpcClient := solanaApp.NewClient(testRpcEndpoint, testWsEndpoint)

	key := solana.MustPublicKeyFromBase58(testNonceAccountAddress)
	hash, err := rpcClient.GetNonceAccountHash(ctx, key)
	require.Nil(err)
	require.Equal(testNonceAccountHash, hash.String())
}
