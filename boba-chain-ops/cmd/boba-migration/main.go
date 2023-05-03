package main

import (
	"os"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ledgerwatch/erigon/boba-chain-ops/genesis"
	"github.com/mattn/go-isatty"
	"github.com/urfave/cli/v2"
)

func main() {
	log.Root().SetHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(isatty.IsTerminal(os.Stderr.Fd()))))

	app := &cli.App{
		Name:  "boba-migrate",
		Usage: "Write allocation data from the legacy data to a json file for erigon",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "db-path",
				Usage:    "Path to database",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "alloc-path",
				Usage:    "Path to the alloc file from the legacy data",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "genesis-config-path",
				Usage:    "Path to the genesis config file",
				Required: true,
			},
		},
		Action: func(ctx *cli.Context) error {
			dbPath := ctx.String("db-path")
			allocPath := ctx.String("alloc-path")
			genesisConfigPath := ctx.String("genesis-config-path")
			if err := genesis.MigrateDB(dbPath, allocPath, genesisConfigPath); err != nil {
				return err
			}
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Crit("critical error exits", "err", err)
	}
}
