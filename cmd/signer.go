package cmd

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/config"
	"github.com/MixinNetwork/safe/messenger"
	"github.com/MixinNetwork/safe/signer"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
	"github.com/gofrs/uuid/v5"
	"github.com/mdp/qrterminal"
	"github.com/shopspring/decimal"
	"github.com/urfave/cli/v2"
)

func SignerBootCmd(c *cli.Context) error {
	ctx := context.Background()

	version := c.App.Metadata["VERSION"].(string)
	ua := fmt.Sprintf("Mixin Safe Signer (%s)", version)
	resty := mixin.GetRestyClient()
	resty.SetTimeout(time.Second * 30)
	resty.SetHeader("User-Agent", ua)

	mc, err := config.ReadConfiguration(c.String("config"), "signer")
	if err != nil {
		return err
	}
	mc.Signer.MTG.GroupSize = 1
	mc.Signer.MTG.LoopWaitDuration = int64(time.Second)

	db, err := mtg.OpenSQLite3Store(mc.Signer.StoreDir + "/mtg.sqlite3")
	if err != nil {
		return err
	}
	defer db.Close()
	group, err := mtg.BuildGroup(ctx, db, mc.Signer.MTG)
	if err != nil {
		return err
	}
	group.EnableDebug()
	group.SetKernelRPC(mc.Signer.MixinRPC)

	messenger, err := messenger.NewMixinMessenger(ctx, mc.Signer.Messenger())
	if err != nil {
		return err
	}

	kd, err := signer.OpenSQLite3Store(mc.Signer.StoreDir+"/mpc.sqlite3", false)
	if err != nil {
		return err
	}
	defer kd.Close()

	var fromStart bool
	legacyDB := c.String("legacy")
	if legacyDB != "" {
		state, err := kd.SessionsState(ctx)
		if err != nil {
			return err
		}
		actions, err := db.ListActions(ctx, mtg.ActionStateDone, 1)
		if err != nil {
			return err
		}
		if state.Done == 0 && len(actions) == 0 {
			ld, err := signer.OpenSQLite3Store(legacyDB, true)
			if err != nil {
				return err
			}
			err = kd.ImportBackup(ctx, ld)
			if err != nil {
				return err
			}
			err = ld.Close()
			if err != nil {
				return err
			}
			fromStart = true
		}
	}

	s := &mixin.Keystore{
		ClientID:          mc.Signer.MTG.App.AppId,
		SessionID:         mc.Signer.MTG.App.SessionId,
		SessionPrivateKey: mc.Signer.MTG.App.SessionPrivateKey,
		ServerPublicKey:   mc.Signer.MTG.App.ServerPublicKey,
	}
	client, err := mixin.NewFromKeystore(s)
	if err != nil {
		return err
	}
	me, err := client.UserMe(ctx)
	if err != nil {
		return err
	}
	key, err := mixinnet.ParseKeyWithPub(mc.Signer.MTG.App.SpendPrivateKey, me.SpendPublicKey)
	if err != nil {
		return err
	}
	mc.Signer.MTG.App.SpendPrivateKey = key.String()

	node := signer.NewNode(kd, group, messenger, mc.Signer, mc.Keeper.MTG, client)
	node.Boot(ctx, fromStart)

	if mmc := mc.Signer.MonitorConversaionId; mmc != "" {
		go MonitorSigner(ctx, db, kd, mc.Signer, group, mmc, version)
	}

	group.AttachWorker(mc.Signer.AppId, node)
	group.Run(ctx)
	return nil
}

func SignerFundRequest(c *cli.Context) error {
	mc, err := config.ReadConfiguration(c.String("config"), "signer")
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
	mc, err := config.ReadConfiguration(c.String("config"), "signer")
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
	mc, err := config.ReadConfiguration(c.String("config"), "signer")
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
	input.Memo = mtg.EncodeMixinExtraBase64(conf.AppId, extra)
	pay, err := client.VerifyPayment(ctx, input)
	if err != nil {
		return err
	}
	url := "mixin://codes/" + pay.CodeID
	fmt.Println(url)
	qrterminal.GenerateHalfBlock(url, qrterminal.H, os.Stdout)
	return nil
}

func SignerExportLegacyData(c *cli.Context) error {
	ctx := context.Background()

	input := c.String("database")
	if input == "" {
		return fmt.Errorf("empty path of legacy database")
	}
	path := c.String("export")
	if path == "" {
		return fmt.Errorf("empty path of export database")
	}

	ld, err := signer.OpenSQLite3Store(input, true)
	if err != nil {
		return err
	}
	defer ld.Close()
	sd, err := signer.OpenSQLite3Store(path, false)
	if err != nil {
		return err
	}
	defer sd.Close()

	return sd.ImportBackup(ctx, ld)
}
