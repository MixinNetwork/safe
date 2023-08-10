package cmd

import (
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/saver"
	"github.com/urfave/cli/v2"
)

func SaverBootCmd(c *cli.Context) error {
	logger.SetLevel(logger.VERBOSE)
	store, err := saver.OpenSQLite3Store(c.String("store") + "/safe.sqlite3")
	if err != nil {
		return err
	}
	return saver.StartHTTP(store, c.Int("port"))
}
