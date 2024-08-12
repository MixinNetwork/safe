package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/config"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/urfave/cli/v2"
)

// FIXME remove this
func mtgFixCache(ctx context.Context, path string) {
	db, err := common.OpenSQLite3Store(path, "")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	txn, err := db.BeginTx(ctx, nil)
	if err != nil {
		panic(err)
	}
	defer txn.Rollback()

	key := "FIX:0d996abd53c1d8103c024939a2ce2fd67170508b:1"
	row := txn.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&key)
	if err == sql.ErrNoRows {
	} else if err != nil {
		panic(err)
	} else {
		return
	}

	invalidate := "DELETE FROM caches;\n"
	_, err = txn.ExecContext(ctx, invalidate)
	if err != nil {
		panic(err)
	}

	alter := "ALTER TABLE outputs DROP COLUMN mask;\n"
	alter = alter + "ALTER TABLE outputs DROP COLUMN keys;\n"
	alter = alter + "ALTER TABLE outputs DROP COLUMN receivers;\n"
	_, err = txn.ExecContext(ctx, invalidate)
	if err != nil {
		panic(err)
	}

	query := invalidate + alter
	_, err = txn.ExecContext(ctx, "INSERT INTO properties (key, value, created_at, updated_at) VALUES (?, ?, ?, ?)",
		key, query, time.Now().UTC(), time.Now().UTC())
	if err != nil {
		panic(err)
	}
	err = txn.Commit()
	if err != nil {
		panic(err)
	}
}

func KeeperBootCmd(c *cli.Context) error {
	ctx := context.Background()

	version := c.App.Metadata["VERSION"].(string)
	ua := fmt.Sprintf("Mixin Safe Keeper (%s)", version)
	resty := mixin.GetRestyClient()
	resty.SetTimeout(time.Second * 30)
	resty.SetHeader("User-Agent", ua)

	mc, err := config.ReadConfiguration(c.String("config"), "keeper")
	if err != nil {
		return err
	}
	mc.Keeper.MTG.GroupSize = 1
	mc.Signer.MTG.LoopWaitDuration = int64(time.Second)

	mtgFixCache(ctx, mc.Keeper.StoreDir+"/mtg.sqlite3")

	db, err := mtg.OpenSQLite3Store(mc.Keeper.StoreDir + "/mtg.sqlite3")
	if err != nil {
		return err
	}
	defer db.Close()

	group, err := mtg.BuildGroup(ctx, db, mc.Keeper.MTG)
	if err != nil {
		return err
	}
	group.EnableDebug()
	group.SetKernelRPC(mc.Keeper.MixinRPC)

	s := &mixin.Keystore{
		ClientID:          mc.Keeper.MTG.App.AppId,
		SessionID:         mc.Keeper.MTG.App.SessionId,
		SessionPrivateKey: mc.Keeper.MTG.App.SessionPrivateKey,
		ServerPublicKey:   mc.Keeper.MTG.App.ServerPublicKey,
	}
	client, err := mixin.NewFromKeystore(s)
	if err != nil {
		return err
	}
	me, err := client.UserMe(ctx)
	if err != nil {
		return err
	}
	key, err := mixinnet.ParseKeyWithPub(mc.Keeper.MTG.App.SpendPrivateKey, me.SpendPublicKey)
	if err != nil {
		return err
	}
	mc.Keeper.MTG.App.SpendPrivateKey = key.String()

	kd, err := keeper.OpenSQLite3Store(mc.Keeper.StoreDir + "/safe.sqlite3")
	if err != nil {
		return err
	}
	defer kd.Close()
	keeper := keeper.NewNode(kd, group, mc.Keeper, mc.Signer.MTG, client)
	keeper.Boot(ctx)

	if mmc := mc.Keeper.MonitorConversaionId; mmc != "" {
		go MonitorKeeper(ctx, db, kd, mc.Keeper, group, mmc, version)
	}

	group.AttachWorker(mc.Keeper.AppId, keeper)
	group.RegisterDepositEntry(mc.Keeper.AppId, mtg.DepositEntry{
		Destination: mc.Keeper.PolygonKeeperDepositEntry,
		Tag:         "",
	})
	group.Run(ctx)
	return nil
}

func KeeperFundRequest(c *cli.Context) error {
	mc, err := config.ReadConfiguration(c.String("config"), "keeper")
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
