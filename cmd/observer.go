package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/config"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/observer"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/urfave/cli/v2"
)

func ObserverBootCmd(c *cli.Context) error {
	logger.SetLevel(logger.VERBOSE)
	ctx := context.Background()

	mc, err := config.ReadConfiguration(c.String("config"))
	if err != nil {
		return err
	}

	db, err := observer.OpenSQLite3Store(mc.Observer.StoreDir + "/safe.sqlite3")
	if err != nil {
		return err
	}
	defer db.Close()

	kd, err := keeper.OpenSQLite3ReadOnlyStore(mc.Observer.KeeperStoreDir + "/safe.sqlite3")
	if err != nil {
		return err
	}
	defer kd.Close()

	mixin, err := mixin.NewFromKeystore(&mixin.Keystore{
		ClientID:   mc.Observer.App.ClientId,
		SessionID:  mc.Observer.App.SessionId,
		PrivateKey: mc.Observer.App.PrivateKey,
		PinToken:   mc.Observer.App.PinToken,
	})
	if err != nil {
		return err
	}

	node := observer.NewNode(db, kd, mc.Observer, mc.Keeper.MTG, mixin)
	go node.StartHTTP(c.App.Metadata["README"].(string))
	node.Boot(ctx)
	return nil
}

func ObserverImportKeys(c *cli.Context) error {
	ctx := context.Background()

	mc, err := config.ReadConfiguration(c.String("config"))
	if err != nil {
		return err
	}

	db, err := observer.OpenSQLite3Store(mc.Observer.StoreDir + "/safe.sqlite3")
	if err != nil {
		return err
	}
	defer db.Close()

	chain := c.Int("chain")
	publics, err := scanKeyList(c.String("list"), chain)
	if err != nil {
		return err
	}
	return db.WriteObserverKeys(ctx, byte(chain), publics)
}

func scanKeyList(path string, chain int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	switch chain {
	case keeper.SafeChainBitcoin:
	default:
		return nil, fmt.Errorf("invalid chain %d", chain)
	}

	var publics []string
	for scanner.Scan() {
		pub := scanner.Text()
		err := bitcoin.VerifyHolderKey(pub, byte(chain))
		if err != nil {
			return nil, err
		}
		publics = append(publics, pub)
	}
	return publics, nil
}
