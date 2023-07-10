package cmd

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/nfo/store"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/config"
	"github.com/MixinNetwork/safe/messenger"
	"github.com/MixinNetwork/safe/signer"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid"
	"github.com/mdp/qrterminal"
	"github.com/shopspring/decimal"
	"github.com/urfave/cli/v2"
)

func SignerBootCmd(c *cli.Context) error {
	logger.SetLevel(logger.VERBOSE)
	ctx := context.Background()

	mc, err := config.ReadConfiguration(c.String("config"))
	if err != nil {
		return err
	}
	mc.Signer.MTG.GroupSize = 1

	db, err := store.OpenBadger(ctx, mc.Signer.StoreDir+"/mtg")
	if err != nil {
		return err
	}
	defer db.Close()
	group, err := mtg.BuildGroup(ctx, db, mc.Signer.MTG)
	if err != nil {
		return err
	}

	messenger, err := messenger.NewMixinMessenger(ctx, mc.Signer.Messenger())
	if err != nil {
		return err
	}

	kd, err := signer.OpenSQLite3Store(mc.Signer.StoreDir + "/mpc.sqlite3")
	if err != nil {
		return err
	}
	defer kd.Close()

	s := &mixin.Keystore{
		ClientID:   mc.Signer.MTG.App.ClientId,
		SessionID:  mc.Signer.MTG.App.SessionId,
		PrivateKey: mc.Signer.MTG.App.PrivateKey,
		PinToken:   mc.Signer.MTG.App.PinToken,
	}
	client, err := mixin.NewFromKeystore(s)
	if err != nil {
		return err
	}
	err = client.VerifyPin(ctx, mc.Signer.MTG.App.PIN)
	if err != nil {
		return err
	}

	node := signer.NewNode(kd, group, messenger, mc.Signer, mc.Keeper.MTG, client)
	node.Boot(ctx)
	group.AddWorker(node)
	group.Run(ctx)
	return nil
}

func SignerFundRequest(c *cli.Context) error {
	mc, err := config.ReadConfiguration(c.String("config"))
	if err != nil {
		return err
	}
	op := &common.Operation{
		Type:  common.OperationTypeWrapper,
		Id:    uuid.Must(uuid.NewV4()).String(),
		Curve: common.CurveSecp256k1ECDSABitcoin,
	}
	return makeSignerPaymentRequest(mc.Signer, op, mc.Signer.AssetId, decimal.NewFromInt(1000000))
}

func SignerKeygenRequest(c *cli.Context) error {
	mc, err := config.ReadConfiguration(c.String("config"))
	if err != nil {
		return err
	}
	op := &common.Operation{
		Type:  common.OperationTypeKeygenInput,
		Id:    c.String("session"),
		Curve: byte(c.Uint("curve")),
	}
	return makeSignerPaymentRequest(mc.Signer, op, mc.Signer.KeeperAssetId, decimal.NewFromInt(10))
}

func SignerSignRequest(c *cli.Context) error {
	mc, err := config.ReadConfiguration(c.String("config"))
	if err != nil {
		return err
	}
	op := &common.Operation{
		Type:   common.OperationTypeSignInput,
		Id:     c.String("session"),
		Curve:  byte(c.Uint("curve")),
		Public: hex.EncodeToString(common.Fingerprint(c.String("key"))),
		Extra:  []byte(c.String("msg")),
	}
	if op.Curve == common.CurveEdwards25519Mixin {
		mask, err := crypto.KeyFromString(c.String("mask"))
		if err != nil || !mask.CheckKey() {
			return fmt.Errorf("mixin mask %s %v", c.String("mask"), err)
		}
		op.Extra = binary.BigEndian.AppendUint16(mask[:], uint16(c.Int("index")))
		op.Extra = append(op.Extra, c.String("msg")...)
	}
	return makeSignerPaymentRequest(mc.Signer, op, mc.Signer.KeeperAssetId, decimal.NewFromInt(10))
}

func makeSignerPaymentRequest(conf *signer.Configuration, op *common.Operation, assetId string, amount decimal.Decimal) error {
	ctx := context.Background()
	aesKey := common.ECDHEd25519(conf.SharedKey, conf.KeeperPublicKey)

	s := &mixin.Keystore{
		ClientID:   conf.MTG.App.ClientId,
		SessionID:  conf.MTG.App.SessionId,
		PrivateKey: conf.MTG.App.PrivateKey,
		PinToken:   conf.MTG.App.PinToken,
	}
	client, err := mixin.NewFromKeystore(s)
	if err != nil {
		return err
	}
	err = client.VerifyPin(ctx, conf.MTG.App.PIN)
	if err != nil {
		return err
	}

	switch op.Curve {
	case common.CurveSecp256k1ECDSABitcoin:
	case common.CurveSecp256k1ECDSAEthereum:
	case common.CurveSecp256k1SchnorrBitcoin:
	case common.CurveEdwards25519Default:
	case common.CurveEdwards25519Mixin:
	default:
		return fmt.Errorf("CurveSecp256k1ECDSABitcoin:\t\t%d\nCurveSecp256k1SchnorrBitcoin:\t\t%d\nCurveEdwards25519Default:\t%d\nCurveEdwards25519Mixin:\t\t%d\n",
			common.CurveSecp256k1ECDSABitcoin, common.CurveSecp256k1SchnorrBitcoin, common.CurveEdwards25519Default, common.CurveEdwards25519Mixin)
	}

	extra := common.AESEncrypt(aesKey[:], op.Encode(), op.Id)
	input := mixin.TransferInput{
		AssetID: assetId,
		Amount:  amount,
		TraceID: op.Id,
	}
	input.OpponentMultisig.Receivers = conf.MTG.Genesis.Members
	input.OpponentMultisig.Threshold = uint8(conf.MTG.Genesis.Threshold)
	input.Memo = mtg.EncodeMixinExtra("", op.Id, string(extra))
	pay, err := client.VerifyPayment(ctx, input)
	if err != nil {
		return err
	}
	url := "mixin://codes/" + pay.CodeID
	fmt.Println(url)
	qrterminal.GenerateHalfBlock(url, qrterminal.H, os.Stdout)
	return nil
}
