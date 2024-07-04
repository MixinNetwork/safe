package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/urfave/cli/v2"
)

func DecodeOperation(c *cli.Context) error {
	k, err := hex.DecodeString(c.String("key"))
	if err != nil {
		return err
	}

	_, m := mtg.DecodeMixinExtraHEX(c.String("data"))
	b := common.AESDecrypt(k, []byte(m))
	op, err := common.DecodeOperation(b)
	if err != nil {
		return err
	}
	fmt.Println(op)
	return nil
}
