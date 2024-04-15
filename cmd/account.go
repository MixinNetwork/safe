package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/config"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/gofrs/uuid/v5"
	"github.com/mdp/qrterminal"
	"github.com/shopspring/decimal"
	"github.com/urfave/cli/v2"
)

func GenerateTestSafeApproval(c *cli.Context) error {
	chain := c.Int("chain")
	switch chain {
	case keeper.SafeChainBitcoin:
	default:
		return fmt.Errorf("invalid chain %d", chain)
	}

	hash := bitcoin.HashMessageForSignature(c.String("address"), byte(chain))
	kb, err := hex.DecodeString(c.String("key"))
	if err != nil {
		return err
	}
	private, _ := btcec.PrivKeyFromBytes(kb)
	sig := ecdsa.Sign(private, hash)
	fmt.Println(base64.RawURLEncoding.EncodeToString(sig.Serialize()))
	return nil
}

func GenerateTestSafeProposal(c *cli.Context) error {
	chain := c.Int("chain")
	switch chain {
	case keeper.SafeChainBitcoin:
	default:
		return fmt.Errorf("invalid chain %d", chain)
	}

	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		return err
	}
	private, _ := btcec.PrivKeyFromBytes(seed)
	holder := testPublicKey(hex.EncodeToString(private.Serialize()))

	threshold := byte(1)
	total := byte(1)
	receivers := []string{"fcb87491-4fa0-4c2f-b387-262b63cbc112"}
	extra := []byte{threshold, total}
	uid := uuid.FromStringOrNil(receivers[0])
	extra = append(extra, uid.Bytes()...)

	sid := uuid.Must(uuid.NewV4()).String()
	fmt.Printf("session: %s\npublic: %s\nprivate: %x\n", sid, holder, private.Serialize())

	memo := testBuildHolderRequest(sid, holder, common.ActionBitcoinSafeProposeAccount, extra)
	amount := decimal.NewFromFloat(1)
	assetId := "31d2ea9c-95eb-3355-b65b-ba096853bc18"
	return makeKeeperPaymentRequest(c.String("config"), assetId, amount, sid, memo)
}

func testPublicKey(priv string) string {
	seed, _ := hex.DecodeString(priv)
	_, dk := btcec.PrivKeyFromBytes(seed)
	return hex.EncodeToString(dk.SerializeCompressed())
}

func testBuildHolderRequest(id, public string, action byte, extra []byte) string {
	op := &common.Operation{
		Id:     id,
		Type:   action,
		Curve:  common.CurveSecp256k1ECDSABitcoin,
		Public: public,
		Extra:  extra,
	}
	return base64.RawURLEncoding.EncodeToString(op.Encode())
}

func makeKeeperPaymentRequest(path, assetId string, amount decimal.Decimal, sid, memo string) error {
	ctx := context.Background()
	mc, err := config.ReadConfiguration(path)
	if err != nil {
		return err
	}
	conf := mc.Keeper

	s := &mixin.Keystore{
		ClientID:          conf.MTG.App.AppId,
		SessionID:         conf.MTG.App.SessionId,
		SessionPrivateKey: conf.MTG.App.SessionPrivateKey,
		ServerPublicKey:   conf.MTG.App.ServerPublicKey,
	}
	client, err := mixin.NewFromKeystore(s)
	if err != nil {
		return err
	}
	_, err = client.UserMe(ctx)
	if err != nil {
		return err
	}

	input := mixin.TransferInput{
		AssetID: assetId,
		Amount:  amount,
		TraceID: sid,
		Memo:    memo,
	}
	input.OpponentMultisig.Receivers = conf.MTG.Genesis.Members
	input.OpponentMultisig.Threshold = uint8(conf.MTG.Genesis.Threshold)
	pay, err := client.VerifyPayment(ctx, input)
	if err != nil {
		return err
	}
	url := "mixin://codes/" + pay.CodeID
	fmt.Println(url)
	qrterminal.GenerateHalfBlock(url, qrterminal.H, os.Stdout)
	return nil
}
