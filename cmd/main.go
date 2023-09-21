package main

import (
	"os"

	logging "github.com/ipfs/go-log/v2"
	"github.com/urfave/cli/v2"

	"offline-wallet/build"
	cliOff "offline-wallet/cli"
)

var log = logging.Logger("offline-wallet")

func main() {
	local := []*cli.Command{
		initCmd,
		cliOff.WalletCmd,
		cliOff.ActorWithdrawCmd,
		cliOff.MultisigCmd,
	}

	app := &cli.App{
		Name:     "offline-wallet",
		Usage:    "This is a offline wallet.",
		Version:  build.UserVersion(),
		Commands: local,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "repo",
				EnvVars: []string{""},
				Value:   "~/.offline-wallet", // TODO: Consider XDG_DATA_HOME
			},
			&cli.BoolFlag{
				Name: "offline",
				// Hidden: true,
				Usage: "offline mode",
				Value: false,
			},
		},
		Before: func(cctx *cli.Context) error {
			logging.SetLogLevel("offline-wallet", cctx.String("log-level"))
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Errorf("%+v", err)
		os.Exit(1)
		return
	}
}
