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

	b, err := hex.DecodeString(c.String("data"))
	if err != nil {
		return err
	}

	_, _, m := mtg.DecodeMixinExtra(string(b))
	b = common.AESDecrypt(k, []byte(m))
	op, err := common.DecodeOperation(b)
	if err != nil {
		return err
	}
	fmt.Println(op)
	return nil
}
