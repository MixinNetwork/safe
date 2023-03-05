package cmd

import (
	"context"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/config"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/urfave/cli/v2"
)

func MTGUnlockKeeperRequest(c *cli.Context) error {
	logger.SetLevel(logger.VERBOSE)
	ctx := context.Background()

	mc, err := config.ReadConfiguration(c.String("config"))
	if err != nil {
		return err
	}
	conf := mc.Keeper

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

	req, err := client.CreateMultisig(ctx, mixin.MultisigActionUnlock, c.String("raw"))
	if err != nil {
		return err
	}
	return client.UnlockMultisig(ctx, req.RequestID, conf.MTG.App.PIN)
}
