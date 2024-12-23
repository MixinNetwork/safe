package computer

import (
	"context"
	"testing"

	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/require"
)

const (
	testRpcEndpoint         = "https://api.mainnet-beta.solana.com"
	testWsEndpoint          = "wss://api.mainnet-beta.solana.com"
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
	testUserNonceAccountHash2   = "FrqtK1eTYLJtR6mGNaBWF6qyfpjTqk1DJaAQdAm31Xc1"
)

func TestComputerSolana(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	ctx = common.EnableTestEnvironment(ctx)
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
			SolanaAsset: true,
			Amount:      10000000,
			Destination: user.PublicKey(),
		},
		{
			Mint:        mint.PublicKey(),
			Amount:      10000000,
			Destination: user.PublicKey(),
			Decimals:    8,
		},
	}
	tx, mints, err := rpcClient.TransferTokens(ctx, testPayerPrivKey, testMtgPrivKey, nonce, transfers)
	require.Nil(err)
	require.Len(mints, 1)
	_, err = tx.Sign(solanaApp.BuildSignersGetter([]solana.PrivateKey{payer, mtg, mint}...))
	require.Nil(err)
	require.Equal(
		"AwAFC83FbI0IejAbIRRLKrXhKGtQpdlB7gL2JIjbAwi5Q9LWh+mBbeScWnn/TP5dr0xFz7V2EwYACKukUWzjrDD6k9RkLLxwGoFACZKqiUySwUhPyCGVNzc8O4yjc3M7XUcMbrrUr3mVJkS9gIgbOTSz4nitL07uo2FOHEKDUNkF6sTsN2b4E5F03p01h6e5Eo461IsTij6ElObZW4qVdaayYWQJxEz9jCArEmdI/aeLBT2ByII/+LALSw2bXMmDOWEsHAan1RcZLFaO4IqEX3PSl4jPA1wxRbIas0TYBi6pQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG3fbh12Whk9nL4UbO63msHLSF7V9bN5E6jPWFfv8AqQan1RcZLFxRIYzJTD1K8X9Y2u4Im6H9ROPb2YoAAAAAjJclj04kifG7PRApFI4NgwtaE5na/xCEBI572Nvp+Fnt4V4o90OzKUDLSaoj1tCx8aTOnuRwGYtkr4MfIunrSwYHAwMGAAQEAAAABwIBBAwCAAAAgJaYAAAAAAAHAgACNAAAAABgTRYAAAAAAFIAAAAAAAAABt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKkIAQJDFAiH6YFt5Jxaef9M/l2vTEXPtXYTBgAIq6RRbOOsMPqT1AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoHAAUEAgcICQAIAwIFAQkHgJaYAAAAAAA=",
		tx.Message.ToBase64(),
	)

	rawTx := "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ac42de2968e76d2593c3219c16053063a1475de02156e927ed104ccda220602fe6eb85c968a34d1d2747750a6b44af3f1dd799bb242df7cd4e5c4f798cf67a0e80020007153766f8139174de9d3587a7b9128e3ad48b138a3e8494e6d95b8a9575a6b26164b1a8e0a5956ebe519325680281d010020842fd95646649040f4e310cd7c1f2cfc222240d341cac720a3dfcb2109722ce3462f45c0572429fd45a231c2a65906c8c71714aa915774ca3f3b407a423a268912b84216876107bafadaae1b6f534a91afb3a60bf9ef330bebc2d7b3d74cf8b1db7bf7e9dc4b24607cfad3dfa8946e5b7e6e669879de18a74eb48c88ab01613548724d144310d44a1bd22f881b3a139a884d196a23652cf843afea111e291522c65515b6f007779c6ebfa1638b8249bd7630efe890d106b719c7b2c6aec651fa682e1361e41aa262d5cc7836f04837f1e9eafcf0b38fa03bf45db93f68285e291b3811963f36ce936bbf73cdb2f235870b6d496fd128c46cf347158fbadaf6bd8341692e5571ab0d7c5a8a67de3696216935df72653638b99a63c11b1516684d321992a6ae5f015c50fe9a22f9c44c3f0b7fab96272db243bd9aa1acb6c7c78b360199fc2b75d2d577b571bee1a4371878f205ee83fe0eba1e8bb97e6ff11236d29ab3e060ce15b29575e72cfb4f75009c44cfd8c202b126748fda78b053d81c8823ff8b00b4b0d9b5cc98339612c1c0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000a5d5ca9e04cf5db590b714ba2fe32cb159133fc1c192b72257fd07d39cb0401e816e66630c3bb724dc59e49f6cc4306e603a6aacca06fa3e34e2b40ad5979d8d069b8857feab8184fb687f634618c035dac439dc1aeb3b5598a0f00000000001642cbc701a81400992aa894c92c1484fc8219537373c3b8ca373733b5d470c6e06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90000000000000000000000000000000000000000000000000000000000000000af47a52a4c0449f19d170a72232a4007cb70869db23c578c85a321dac7b69d32070e00090378fd4500000000000e000502c02709000f0d0010021112030405061313141520e992d18ecf6840bc000000000000000001000000000000002d1e696700000000140200077c030000003766f8139174de9d3587a7b9128e3ad48b138a3e8494e6d95b8a9575a6b2616420000000000000004239486246527646624b31667879775a546b3744516f48466e774670424b504770a23d0000000000a50000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a913040711001501010f150000010802090a0b0c070d030415141316171112063b4dffae527d1dc92e0c3bf9fff4c40600083bf9ffbcc406000000000000000000000000000000000080841e0000000000d0471f00000000000101011303070000010901198f1f4c3a452263d413b2cd17ebcbc1a0e5887364e6261a12a81792ea165a3e0003050703"
	rb := common.DecodeHexOrPanic(rawTx)
	tx, err = solana.TransactionFromBytes(rb)
	require.Nil(err)
	_, err = tx.PartialSign(solanaApp.BuildSignersGetter(payer, user))
	require.Nil(err)
	require.Len(tx.Signatures, 2)
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
