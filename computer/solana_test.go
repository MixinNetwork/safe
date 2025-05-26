package computer

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/crypto"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

const (
	testRpcEndpoint         = "https://api.mainnet-beta.solana.com"
	testNonceAccountAddress = "FLq1XqAbaFjib59q6mRDRFEzoQnTShWu1Vis7q57HKtd"
	testNonceAccountHash    = "8j6J9Z8GdbkY1VsJKuKk799nGfkNchMGZ9LY2bdvtYrZ"

	testPayerPrivKey            = "56HtVW5YQ9Xi8MTeQFAWdSuzV17mrDAr1AUCYzTdx36VLvsodA89eSuZd6axrufzo4tyoUNdgjDpm4fnLJLRcXmF"
	testUserNonceAccountPrivKey = "5mCExzNoFSY8UwVbGYPiVtmfeWtqoNeprRymq4wU7yZwWxVCrpXoX7F2KSEFrbVEPRSUjejAeNBbFYMhC3iiu4F5"
	testUserNonceAccountHash    = "FrqtK1eTYLJtR6mGNaBWF6qyfpjTqk1DJaAQdAm31Xc1"
)

func TestComputerSolana(t *testing.T) {
	require := require.New(t)
	ctx, nodes, _ := testPrepare(require)
	testFROSTPrepareKeys(ctx, require, nodes, testFROSTKeys1, "fb17b60698d36d45bc624c8e210b4c845233c99a7ae312a27e883a8aa8444b9b")
	testFROSTPrepareKeys(ctx, require, nodes, testFROSTKeys2, "4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295")

	node := nodes[0]
	count, err := node.store.CountKeys(ctx)
	require.Nil(err)
	require.Equal(2, count)
	key, err := node.store.ReadLatestPublicKey(ctx)
	require.Nil(err)
	require.Equal("4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295", key)
	payer, err := solana.PrivateKeyFromBase58(testPayerPrivKey)
	require.Nil(err)
	require.Equal("ErFBVPGYmi8Vjuf1jAfmZLzyFHLnF9c1MNhfcEQGdgMb", payer.PublicKey().String())
	addr := solana.PublicKeyFromBytes(common.DecodeHexOrPanic(key))
	require.Equal("5YLSixqjK2m8ECirGaco8tHSn2Uc4aY7cLPoMSMptsgG", addr.String())

	nonceAccount := solana.MustPrivateKeyFromBase58(testUserNonceAccountPrivKey)
	require.Equal("DaJw3pa9rxr25AT1HnQnmPvwS4JbnwNvQbNLm8PJRhqV", nonceAccount.PublicKey().String())
	nonceHash := solana.MustHashFromBase58(testUserNonceAccountHash)

	amount, _ := decimal.NewFromString("0.001")

	b := solana.NewTransactionBuilder()
	b.SetRecentBlockHash(nonceHash)
	b.SetFeePayer(payer.PublicKey())
	b.AddInstruction(system.NewAdvanceNonceAccountInstruction(
		nonceAccount.PublicKey(),
		solana.SysVarRecentBlockHashesPubkey,
		payer.PublicKey(),
	).Build())
	b.AddInstruction(system.NewTransferInstruction(
		decimal.New(1, 9).Mul(amount).BigInt().Uint64(),
		addr,
		addr,
	).Build())
	tx, err := b.Build()
	require.Nil(err)
	_, err = tx.PartialSign(solanaApp.BuildSignersGetter(payer))
	require.Nil(err)

	testFROSTSign(ctx, require, nodes, nonceAccount.PublicKey().String(), key, tx)
}

func TestGetNonceAccountHash(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	rpc := testRpcEndpoint
	rpcClient := solanaApp.NewClient(rpc)

	priv, err := solana.NewRandomPrivateKey()
	require.Nil(err)
	asset, err := bot.ReadAsset(ctx, "965e5c6e-434c-3fa9-b780-c50f43cd955c")
	require.Nil(err)
	as := []*solanaApp.DeployedAsset{
		{
			AssetId:  "965e5c6e-434c-3fa9-b780-c50f43cd955c",
			ChainId:  "43d61dcd-e413-450d-80b8-101d5e903357",
			Address:  priv.PublicKey().String(),
			Decimals: 9,

			Uri:        "https://kernel.mixin.dev/objects/0a67b46d4b7ee61944559444f333394a40af3b969a3ac342442635eb0840859c/content",
			Asset:      asset,
			PrivateKey: &priv,
		},
	}
	tx, err := rpcClient.CreateMints(ctx, solana.MPK("25BLr41rQN23SkiY6gWS8NtuaiKHHTki8CwjzuXPPpks"), solana.MPK("5v1eqBfJQkX4JYCi43v7eApXERTNakRBJX1d6Ax6KRzK"), as)
	require.Nil(err)
	_, err = tx.PartialSign(solanaApp.BuildSignersGetter(solana.MustPrivateKeyFromBase58("4KJCmV75fw8pZ4DQe4nnKYn4fjAYJVbCugBvXRfmateJrp4CLzfacQCetM3d5LjCceXNKx6shkvFZvihStGjjGy1")))
	require.Nil(err)
	fmt.Println(tx)
	hash, err := rpcClient.SendTransaction(ctx, tx)
	fmt.Println(hash, err)
}

func testFROSTSign(ctx context.Context, require *require.Assertions, nodes []*Node, nonce, public string, tx *solana.Transaction) {
	msg, err := tx.Message.MarshalBinary()
	require.Nil(err)
	require.Equal(
		"02000205cdc56c8d087a301b21144b2ab5e1286b50a5d941ee02f62488db0308b943d2d64375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295bad4af79952644bd80881b3934b3e278ad2f4eeea3614e1c428350d905eac4ec06a7d517192c568ee08a845f73d29788cf035c3145b21ab344d8062ea94000000000000000000000000000000000000000000000000000000000000000000000dcc859c62859a93c7ca37d6f180d63ba1f1ccadc68373b6605c4358bd77983060204030203000404000000040201010c0200000040420f0000000000",
		hex.EncodeToString(msg),
	)

	now := time.Now().UTC()
	id := uuid.Must(uuid.NewV4()).String()
	sid := common.UniqueId(id, now.String())
	call := &store.SystemCall{
		RequestId:        id,
		Superior:         id,
		RequestHash:      "4375bcd5726aadfdd159135441bbe659c705b37025c5c12854e9906ca8500295",
		Type:             store.CallTypeMain,
		NonceAccount:     nonce,
		Public:           public,
		MessageHash:      crypto.Sha256Hash(msg).String(),
		Raw:              tx.MustToBase64(),
		State:            common.RequestStatePending,
		WithdrawalTraces: sql.NullString{Valid: true, String: ""},
		Signature:        sql.NullString{Valid: false},
		RequestSignerAt:  sql.NullTime{Valid: false},
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	pub := common.Fingerprint(call.Public)
	pub = append(pub, []byte{0, 0, 0, 0, 0, 0, 0, 0}...)
	for _, node := range nodes {
		err := node.store.TestWriteCall(ctx, call)
		require.Nil(err)
		session := &store.Session{
			Id:         sid,
			RequestId:  call.RequestId,
			MixinHash:  crypto.Sha256Hash([]byte(id)).String(),
			MixinIndex: 0,
			Index:      0,
			Operation:  OperationTypeSignInput,
			Public:     hex.EncodeToString(pub),
			Extra:      call.MessageHex(),
			CreatedAt:  now,
		}
		err = node.store.TestWriteSignSession(ctx, call, []*store.Session{session})
		require.Nil(err)
	}

	for _, node := range nodes {
		testWaitOperation(ctx, node, sid)
	}

	node := nodes[0]
	for {
		s, err := node.store.ReadSystemCallByRequestId(ctx, call.RequestId, common.RequestStatePending)
		require.Nil(err)
		if s != nil && s.Signature.Valid {
			return
		}
		time.Sleep(5 * time.Second)
	}
}
