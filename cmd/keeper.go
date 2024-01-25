package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/MixinNetwork/nfo/store"
	"github.com/MixinNetwork/safe/config"
	"github.com/MixinNetwork/safe/custodian"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/urfave/cli/v2"
)

func KeeperBootCmd(c *cli.Context) error {
	ctx := context.Background()

	ua := fmt.Sprintf("Mixin Safe Keeper (%s)", config.AppVersion)
	resty := mixin.GetRestyClient()
	resty.SetTimeout(time.Second * 30)
	resty.SetHeader("User-Agent", ua)

	mc, err := config.ReadConfiguration(c.String("config"))
	if err != nil {
		return err
	}
	mc.Keeper.MTG.GroupSize = 1
	config.HandleDevConfig(mc.Dev)

	db, err := store.OpenBadger(ctx, mc.Keeper.StoreDir+"/mtg")
	if err != nil {
		return err
	}
	defer db.Close()

	group, err := mtg.BuildGroup(ctx, db, mc.Keeper.MTG)
	if err != nil {
		return err
	}

	cd, err := custodian.OpenSQLite3Store(mc.Keeper.StoreDir + "/custodian.sqlite3")
	if err != nil {
		return err
	}
	defer cd.Close()
	custodian := custodian.NewWorker(cd)
	custodian.Boot(ctx)

	kd, err := keeper.OpenSQLite3Store(mc.Keeper.StoreDir + "/safe.sqlite3")
	if err != nil {
		return err
	}
	defer kd.Close()
	keeper := keeper.NewNode(kd, group, mc.Keeper, mc.Signer.MTG)
	keeper.Boot(ctx)

	if mmc := mc.Keeper.MonitorConversaionId; mmc != "" {
		go MonitorKeeper(ctx, db, kd, mc.Keeper, group, mmc)
	}

	group.AddWorker(custodian)
	group.AddWorker(keeper)
	group.Run(ctx)
	return nil
}

func KeeperFundRequest(c *cli.Context) error {
	mc, err := config.ReadConfiguration(c.String("config"))
	if err != nil {
		return err
	}
	assetId := mc.Keeper.AssetId
	if c.String("asset") != "" {
		assetId = c.String("asset")
	}
	amount := decimal.RequireFromString(c.String("amount"))
	traceId := uuid.Must(uuid.NewV4()).String()
	return makeKeeperPaymentRequest(c.String("config"), assetId, amount, traceId, "")
}
