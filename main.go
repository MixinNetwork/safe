package main

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/MixinNetwork/safe/cmd"
	"github.com/urfave/cli/v2"
)

//go:embed README.md
var README string

//go:embed VERSION
var VERSION string

func main() {
	VERSION = strings.TrimSpace(VERSION)
	if strings.Contains(VERSION, "COMMIT") {
		panic("please build the application using make command.")
	}
	app := &cli.App{
		Name:                 "safe",
		Usage:                "Mixin Safe",
		Version:              VERSION,
		EnableBashCompletion: true,
		Metadata: map[string]any{
			"README":  README,
			"VERSION": VERSION,
		},
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
				Name:   "importobserverkeys",
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
				Name:   "fillobserveraccountants",
				Usage:  "Fill more observer accountant outputs",
				Action: cmd.ObserverFillAccountants,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
					&cli.IntFlag{
						Name:  "chain",
						Value: 1,
						Usage: "The chain type of public keys",
					},
					&cli.StringFlag{
						Name:  "input",
						Usage: "The SegWit UTXO to fill new outputs",
					},
					&cli.StringFlag{
						Name:  "key",
						Usage: "The private key of the input",
					},
					&cli.Int64Flag{
						Name:  "satoshi",
						Usage: "The input satoshi amount",
					},
					&cli.Int64Flag{
						Name:  "count",
						Usage: "The total outputs count",
					},
					&cli.Int64Flag{
						Name:  "fee",
						Usage: "The fee rate in sat/vB",
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
				Name:   "mtgrevokekeeper",
				Usage:  "Revoke a keeper MTG transaction request",
				Action: cmd.MTGRevokeKeeperRequest,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.mixin/safe/config.toml",
						Usage:   "The configuration file path",
					},
					&cli.StringFlag{
						Name:  "id",
						Usage: "The multisig transaction request id to revoke",
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
				Action: cmd.GenerateObserverKeys,
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "chain",
						Usage: "The chain type of public keys",
					},
					&cli.UintFlag{
						Name:  "offset",
						Usage: "The account offset",
						Value: 1,
					},
					&cli.UintFlag{
						Name:  "count",
						Usage: "The total accounts count",
						Value: 1000,
					},
					&cli.StringFlag{
						Name:  "seed",
						Usage: "The 64 bytes master seed for the coin",
					},
					&cli.StringFlag{
						Name:  "list",
						Value: "/tmp/mixin-safe-observers-list",
						Usage: "The observer public keys file",
					},
					&cli.BoolFlag{
						Name:  "private",
						Value: false,
						Usage: "Append private key to the keys list",
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
			{
				Name:   "saver",
				Usage:  "Run the saver for signer backup",
				Action: cmd.SaverBootCmd,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "store",
						Value: "~/.mixin/safe/saver",
						Usage: "The saver database directory",
					},
					&cli.StringFlag{
						Name:  "port",
						Value: "9999",
						Usage: "The saver HTTP port to listen",
					},
				},
			},
			{
				Name:   "addnodetokentosaver",
				Usage:  "Register a signer node token to the saver database",
				Action: cmd.AddSaverNodeToken,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "store",
						Value: "~/.mixin/safe/saver",
						Usage: "The saver database directory",
					},
					&cli.StringFlag{
						Name:  "id",
						Usage: "A valid signer node app id",
					},
				},
			},
			{
				Name:   "exportKeeperLegacyData",
				Usage:  "Export data of Legacy Mixin Network from keeper node",
				Action: cmd.KeeperExportLegacyData,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "database",
						Usage: "The legacy database backup from keeper",
					},
					&cli.StringFlag{
						Name:  "export",
						Usage: "The export database path",
					},
				},
			},
			{
				Name:   "exportSignerLegacyData",
				Usage:  "Export data of Legacy Mixin Network from signer node",
				Action: cmd.SignerExportLegacyData,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "database",
						Usage: "The legacy database backup from keeper",
					},
					&cli.StringFlag{
						Name:  "export",
						Usage: "The export database path",
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
