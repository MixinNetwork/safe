package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/urfave/cli/v2"
)

func DecodeOperation(c *cli.Context) error {
	k, err := hex.DecodeString(c.String("key"))
	if err != nil {
		return err
	}

	b, err := hex.DecodeString(c.String("data"))
	if err != nil {
		return err
	}

	msp := mtg.DecodeMixinExtra(string(b))
	b = common.AESDecrypt(k, []byte(msp.M))
	op, err := common.DecodeOperation(b)
	if err != nil {
		return err
	}
	fmt.Println(op)
	return nil
}

func GenerateTestObserverKeys(c *cli.Context) error {
	chain := c.Int("chain")
	switch chain {
	case keeper.SafeChainBitcoin:
	default:
		return fmt.Errorf("invalid chain %d", chain)
	}

	pubF, err := os.Create(c.String("list") + ".pub")
	if err != nil {
		return err
	}
	defer pubF.Close()
	privF, err := os.Create(c.String("list") + ".priv")
	if err != nil {
		return err
	}
	defer privF.Close()

	for i := 0; i < 1024; i++ {
		seed := make([]byte, 64)
		_, err := rand.Read(seed)
		if err != nil {
			return err
		}
		priv, publicKey := btcec.PrivKeyFromBytes(seed[:32])
		pub := hex.EncodeToString(publicKey.SerializeCompressed())
		code := hex.EncodeToString(seed[32:])
		err = bitcoin.CheckDerivation(pub, seed[32:], 1000)
		if err != nil {
			panic(err)
		}
		_, err = pubF.WriteString(pub + ":" + code + "\n")
		if err != nil {
			return err
		}
		_, err = privF.WriteString(pub + ":" + code + ":" + hex.EncodeToString(priv.Serialize()) + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}
