package cmd

import (
	"context"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/config"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/urfave/cli/v2"
)

func MTGRevokeKeeperRequest(c *cli.Context) error {
	logger.SetLevel(logger.VERBOSE)
	ctx := context.Background()

	mc, err := config.ReadConfiguration(c.String("config"), "keeper")
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

	_, err = client.SafeUnlockMultisigRequest(ctx, c.String("id"))
	return err
}
