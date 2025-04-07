package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/computer"
	"github.com/MixinNetwork/safe/config"
	"github.com/MixinNetwork/safe/messenger"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
	"github.com/urfave/cli/v2"
)

func ComputerBootCmd(c *cli.Context) error {
	ctx := context.Background()

	version := c.App.Metadata["VERSION"].(string)
	ua := fmt.Sprintf("Mixin Computer (%s)", version)
	resty := mixin.GetRestyClient()
	resty.SetTimeout(time.Second * 30)
	resty.SetHeader("User-Agent", ua)

	mc, err := config.ReadConfiguration(c.String("config"), "computer")
	if err != nil {
		return err
	}
	mc.Computer.MTG.GroupSize = 1
	mc.Computer.MTG.LoopWaitDuration = int64(time.Second)

	db, err := mtg.OpenSQLite3Store(mc.Computer.StoreDir + "/mtg.sqlite3")
	if err != nil {
		return err
	}
	defer db.Close()

	group, err := mtg.BuildGroup(ctx, db, mc.Computer.MTG)
	if err != nil {
		return err
	}
	group.EnableDebug()
	group.SetKernelRPC(mc.Computer.MixinRPC)

	s := &mixin.Keystore{
		ClientID:          mc.Computer.MTG.App.AppId,
		SessionID:         mc.Computer.MTG.App.SessionId,
		SessionPrivateKey: mc.Computer.MTG.App.SessionPrivateKey,
		ServerPublicKey:   mc.Computer.MTG.App.ServerPublicKey,
	}
	client, err := mixin.NewFromKeystore(s)
	if err != nil {
		return err
	}
	me, err := client.UserMe(ctx)
	if err != nil {
		return err
	}
	key, err := mixinnet.ParseKeyWithPub(mc.Computer.MTG.App.SpendPrivateKey, me.SpendPublicKey)
	if err != nil {
		return err
	}
	mc.Computer.MTG.App.SpendPrivateKey = key.String()

	messenger, err := messenger.NewMixinMessenger(ctx, mc.Computer.Messenger())
	if err != nil {
		return err
	}

	kd, err := computer.OpenSQLite3Store(mc.Computer.StoreDir + "/computer.sqlite3")
	if err != nil {
		return err
	}
	defer kd.Close()
	computer := computer.NewNode(kd, group, messenger, mc.Computer, client)
	computer.Boot(ctx, version)

	if mmc := mc.Computer.MonitorConversationId; mmc != "" {
		go MonitorComputer(ctx, computer, client, db, kd, mc.Computer, group, mmc, version)
	}

	group.AttachWorker(mc.Computer.AppId, computer)
	group.RegisterDepositEntry(mc.Computer.AppId, mtg.DepositEntry{
		Destination: mc.Computer.SolanaDepositEntry,
		Tag:         "",
	})
	group.Run(ctx)
	return nil
}
