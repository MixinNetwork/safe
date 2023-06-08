package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:                 "governance",
		Usage:                "Mixin Safe Governance",
		Version:              "0.0.1",
		EnableBashCompletion: true,
		Commands:             []*cli.Command{},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}
