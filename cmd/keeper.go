package cmd

import (
	"context"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/nfo/store"
	"github.com/MixinNetwork/safe/config"
	"github.com/MixinNetwork/safe/custodian"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/gofrs/uuid"
	"github.com/shopspring/decimal"
	"github.com/urfave/cli/v2"
)

func KeeperBootCmd(c *cli.Context) error {
	logger.SetLevel(logger.VERBOSE)
	ctx := context.Background()

	mc, err := config.ReadConfiguration(c.String("config"))
	if err != nil {
		return err
	}
	mc.Keeper.MTG.GroupSize = 1

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
		go MonitorKeeper(ctx, kd, mc.Keeper.MTG, mmc)
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
