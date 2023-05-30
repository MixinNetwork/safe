package cmd

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

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

func scanKeyList(path string, chain int) (map[string]string, error) {
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

	publics := make(map[string]string)
	for scanner.Scan() {
		hd := scanner.Text()
		hdp := strings.Split(hd, ":")
		if len(hdp) != 2 {
			return nil, fmt.Errorf("invalid pair %s", hd)
		}
		pub, code := hdp[0], hdp[1]
		err := bitcoin.VerifyHolderKey(pub)
		if err != nil {
			return nil, fmt.Errorf("invalid pub %s", hd)
		}

		chainCode, err := hex.DecodeString(code)
		if err != nil || len(chainCode) != 32 {
			return nil, fmt.Errorf("invalid code %s", hd)
		}
		publics[pub] = code
	}
	return publics, nil
}
