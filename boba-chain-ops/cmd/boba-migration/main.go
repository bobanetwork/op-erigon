package main

import (
	"os"

	"github.com/c2h5oh/datasize"
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
			&cli.StringFlag{
				Name:  "db-size-limit",
				Usage: "Maximum size of the mdbx database.",
				Value: (8 * datasize.TB).String(),
			},
			&cli.StringFlag{
				Name:  "log-level",
				Usage: "Log level",
				Value: "info",
			},
		},
		Action: func(ctx *cli.Context) error {
			dbPath := ctx.String("db-path")
			allocPath := ctx.String("alloc-path")
			genesisConfigPath := ctx.String("genesis-config-path")
			mdbxDBSize := ctx.String("db-size-limit")

			logLevel, err := log.LvlFromString(ctx.String("log-level"))
			if err != nil {
				logLevel = log.LvlInfo
				if ctx.String("log-level") != "" {
					log.Warn("invalid server.log_level set: " + ctx.String("log-level"))
				}
			}
			log.Root().SetHandler(
				log.LvlFilterHandler(
					logLevel,
					log.StreamHandler(os.Stdout, log.JSONFormat()),
				),
			)

			if err := genesis.MigrateDB(dbPath, allocPath, genesisConfigPath, mdbxDBSize); err != nil {
				return err
			}
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Crit("critical error exits", "err", err)
	}
}
