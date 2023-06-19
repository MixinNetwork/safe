package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/MixinNetwork/safe/cmd"
	"github.com/urfave/cli/v2"
)

//go:embed README.md
var README string

func main() {
	app := &cli.App{
		Name:                 "safe",
		Usage:                "Mixin Safe",
		Version:              "0.7.2",
		EnableBashCompletion: true,
		Metadata:             map[string]any{"README": README},
		Commands: []*cli.Command{
			{
				Name:   "signer",
				Usage:  "Run the signer node",
				Action: cmd.SignerBootCmd,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
				},
			},
			{
				Name:   "keygen",
				Usage:  "Request keygen",
				Action: cmd.SignerKeygenRequest,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
					&cli.StringFlag{
						Name:    "session",
						Aliases: []string{"s"},
						Usage:   "The unique request UUID",
					},
					&cli.UintFlag{
						Name:  "curve",
						Usage: "The curve",
					},
				},
			},
			{
				Name:   "sign",
				Usage:  "Request sign",
				Action: cmd.SignerSignRequest,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
					&cli.StringFlag{
						Name:    "session",
						Aliases: []string{"s"},
						Usage:   "The unique request UUID",
					},
					&cli.StringFlag{
						Name:    "key",
						Aliases: []string{"k"},
						Usage:   "The public key",
					},
					&cli.StringFlag{
						Name:    "msg",
						Aliases: []string{"m"},
						Usage:   "The message",
					},
					&cli.UintFlag{
						Name:  "curve",
						Usage: "The curve",
					},
					&cli.StringFlag{
						Name:  "mask",
						Usage: "The mixin output mask",
					},
					&cli.IntFlag{
						Name:  "index",
						Usage: "The mixin output index",
					},
				},
			},
			{
				Name:   "keeper",
				Usage:  "Run the keeper node",
				Action: cmd.KeeperBootCmd,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
				},
			},
			{
				Name:   "observer",
				Usage:  "Run the observer node",
				Action: cmd.ObserverBootCmd,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
				},
			},
			{
				Name:   "import",
				Usage:  "Import observer public keys",
				Action: cmd.ObserverImportKeys,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
					&cli.StringFlag{
						Name:  "list",
						Usage: "The observer public keys file",
					},
					&cli.IntFlag{
						Name:  "chain",
						Usage: "The chain type of public keys",
					},
				},
			},
			{
				Name:   "decode",
				Usage:  "Decode an operation data",
				Action: cmd.DecodeOperation,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "key",
						Aliases: []string{"k"},
						Usage:   "The AES key",
					},
					&cli.StringFlag{
						Name:    "data",
						Aliases: []string{"d"},
						Usage:   "The operation data",
					},
				},
			},
			{
				Name:   "mtgfundsigner",
				Usage:  "Fund signer with the asset, please do multiple funds for more UTXO",
				Action: cmd.SignerFundRequest,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
				},
			},
			{
				Name:   "mtgunlockkeeper",
				Usage:  "Unlock a keeper MTG transaction request",
				Action: cmd.MTGUnlockKeeperRequest,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
					&cli.StringFlag{
						Name:  "raw",
						Usage: "The raw transaction to unlock",
					},
				},
			},
			{
				Name:   "mtgfundkeeper",
				Usage:  "Fund keeper with the asset, please do multiple funds for more UTXO",
				Action: cmd.KeeperFundRequest,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
					&cli.StringFlag{
						Name:  "asset",
						Usage: "The optional asset id to fund the keeper mtg",
					},
					&cli.StringFlag{
						Name:  "amount",
						Value: "1000000000",
						Usage: "The optional amount to fund the keeper mtg",
					},
				},
			},
			{
				Name:   "generate",
				Usage:  "Generate observer keys list",
				Action: cmd.GenerateTestObserverKeys,
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "chain",
						Usage: "The chain type of public keys",
					},
					&cli.StringFlag{
						Name:  "list",
						Value: "/tmp/mixin-safe-observers-list",
						Usage: "The observer public keys file",
					},
				},
			},
			{
				Name:   "proposeaccount",
				Usage:  "Propose a safe account",
				Action: cmd.GenerateTestSafeProposal,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
					&cli.IntFlag{
						Name:  "chain",
						Usage: "The chain type of public keys",
					},
				},
			},
			{
				Name:   "approveaccount",
				Usage:  "Approve a safe account",
				Action: cmd.GenerateTestSafeApproval,
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "chain",
						Usage: "The chain type of public keys",
					},
					&cli.StringFlag{
						Name:  "key",
						Usage: "The holder private key",
					},
					&cli.StringFlag{
						Name:  "address",
						Usage: "The safe address",
					},
				},
			},
			{
				Name:   "proposetransaction",
				Usage:  "Propose a safe transaction",
				Action: cmd.GenerateTestTransactionProposal,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
					&cli.IntFlag{
						Name:  "chain",
						Usage: "The chain type of public keys",
					},
					&cli.StringFlag{
						Name:  "key",
						Usage: "The holder private key",
					},
					&cli.StringFlag{
						Name:  "address",
						Usage: "The receiver address",
					},
					&cli.Float64Flag{
						Name:  "amount",
						Usage: "The amount",
					},
				},
			},
			{
				Name:   "approvetransaction",
				Usage:  "Approve a safe transaction",
				Action: cmd.GenerateTestTransactionApproval,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
					&cli.IntFlag{
						Name:  "chain",
						Usage: "The chain type of public keys",
					},
					&cli.StringFlag{
						Name:  "key",
						Usage: "The holder private key",
					},
					&cli.StringFlag{
						Name:  "psbt",
						Usage: "The partially signed Bitcoin transaction",
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}
