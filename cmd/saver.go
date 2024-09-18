package cmd

import (
	"context"
	"fmt"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/saver"
	"github.com/gofrs/uuid/v5"
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

func AddSaverNodeToken(c *cli.Context) error {
	ctx := context.Background()
	nodeId, err := uuid.FromString(c.String("id"))
	if err != nil || nodeId.String() != c.String("id") {
		return fmt.Errorf("node id %s should be valid UUID", c.String("id"))
	}
	store, err := saver.OpenSQLite3Store(c.String("store") + "/safe.sqlite3")
	if err != nil {
		return err
	}
	seed := make([]byte, 64)
	crypto.ReadRand(seed)
	priv := crypto.NewKeyFromSeed(seed)
	err = store.WriteNodePublicKey(ctx, nodeId.String(), priv.Public().String())
	if err != nil {
		return err
	}
	fmt.Printf("node:\t%s\npublic:\t%s\nprivate:\t%s\n", nodeId, priv.Public(), priv)
	return nil
}
