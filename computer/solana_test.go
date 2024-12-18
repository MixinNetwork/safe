package computer

import (
	"context"
	"testing"

	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/require"
)

const (
	testNoncePrivKey    = "5mCExzNoFSY8UwVbGYPiVtmfeWtqoNeprRymq4wU7yZwWxVCrpXoX7F2KSEFrbVEPRSUjejAeNBbFYMhC3iiu4F5"
	testPayerPrivKey    = "56HtVW5YQ9Xi8MTeQFAWdSuzV17mrDAr1AUCYzTdx36VLvsodA89eSuZd6axrufzo4tyoUNdgjDpm4fnLJLRcXmF"
	testRecentBlockHash = "3BeTAqEJvjEvMGT3Gad5zC7aaSLFFJJbzSE9fck5xUFW"
	testRent            = 1447680

	testNonceAddress = "FLq1XqAbaFjib59q6mRDRFEzoQnTShWu1Vis7q57HKtd"
	testNonceHash    = "8j6J9Z8GdbkY1VsJKuKk799nGfkNchMGZ9LY2bdvtYrZ"
)

func TestComputerSolana(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	rpcClient := solanaApp.NewClient("", "")
	key, err := solana.PublicKeyFromBase58(testNonceAddress)
	require.Nil(err)
	hash, err := rpcClient.GetNonceAccountHash(ctx, key)
	require.Nil(err)
	require.Equal(testNonceHash, hash.String())

	tx, err := rpcClient.CreateNonceAccount(ctx, testPayerPrivKey, testNoncePrivKey, testRecentBlockHash, uint64(testRent))
	require.Nil(err)
	require.Equal(
		"AgADBc3FbI0IejAbIRRLKrXhKGtQpdlB7gL2JIjbAwi5Q9LWutSveZUmRL2AiBs5NLPieK0vTu6jYU4cQoNQ2QXqxOwGp9UXGSxWjuCKhF9z0peIzwNcMUWyGrNE2AYuqUAAAAan1RcZLFxRIYzJTD1K8X9Y2u4Im6H9ROPb2YoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgcYc0vfeKh0cijRP3TFQH74rzp+5AMPQEMDGN2KWKjQIEAgABNAAAAAAAFxYAAAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAwECAyQGAAAAzcVsjQh6MBshFEsqteEoa1Cl2UHuAvYkiNsDCLlD0tY=",
		tx.Message.ToBase64(),
	)
	require.Len(tx.Signatures, 2)
	require.Equal("7YfK21L78WjiNh8ZEaRF5Hz9oqJMZWFC47x1ZByqR7wBFtQ8BoEnuNwj6U5yDNMH62oqWvpiwhLgRvhk4Q2AfaZ", tx.Signatures[0].String())
	require.Equal("apkx8Nd6RCAvC4CPAh35XbzXs6wDKwoEqpdushnkveDLyocgVgtroR2av6H2VPfAd1yqLhVaZAqDxbuDbBGpD2W", tx.Signatures[1].String())

}
