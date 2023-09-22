package cli

import (
	"bytes"
	"fmt"
	wallet "offline-wallet/chain/wallet"
	"os"
	"os/signal"
	"syscall"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/network"
	api2 "github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/build"
	"github.com/filecoin-project/lotus/chain/types"
	lcli "github.com/filecoin-project/lotus/cli"
	"github.com/ipfs/go-cid"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
	"golang.org/x/xerrors"
)

var ActorWithdrawCmd = &cli.Command{
	Name:      "withdraw",
	Usage:     "withdraw available balance to beneficiary",
	ArgsUsage: "[MinerAddr] [amount (FIL)]",
	Flags: []cli.Flag{
		&cli.IntFlag{
			Name:  "confidence",
			Usage: "number of block confirmations to wait for",
			Value: int(build.MessageConfidence),
		},
		&cli.BoolFlag{
			Name:  "beneficiary",
			Usage: "send withdraw message from the beneficiary address",
		},
	},
	Before: func(ctx *cli.Context) error {
		fmt.Print("Enter password please(will not display in the terminal): ")

		sigCh := make(chan os.Signal, 1)

		// Notify the channel when SIGINT is received
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-sigCh
			fmt.Println("\nInterrupt signal received. Exiting...")
			os.Exit(1)
		}()

		inpdata, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}

		if string(inpdata) != wallet.Password {
			return xerrors.New("password is not correct, please try again.")
		}

		return nil
	},
	Action: func(cctx *cli.Context) error {
		api, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		// defer acloser()

		walletapi := api.WalletAPI()

		ctx := lcli.ReqContext(cctx)

		if cctx.Args().Len() != 2 {
			return fmt.Errorf("usage: withdraw <MinerAddr> <Amount (FIL)>")
		}

		maddr, err := address.NewFromString(cctx.Args().First())
		if err != nil {
			return err
		}

		f, err := types.ParseFIL(cctx.Args().Get(1))
		if err != nil {
			return xerrors.Errorf("parsing 'amount' argument: %w", err)
		}

		amount := abi.TokenAmount(f)

		var res cid.Cid
		if cctx.IsSet("beneficiary") {
			res, err = walletapi.BeneficiaryWithdrawBalance(ctx, maddr, amount)
		} else {
			res, err = walletapi.ActorWithdrawBalance(ctx, maddr, amount)
		}
		if err != nil {
			return err
		}

		fmt.Printf("Requested withdrawal in message %s\nwaiting for it to be included in a block..\n", res)

		// wait for it to get mined into a block
		wait, err := walletapi.StateWaitMsg(ctx, res, uint64(cctx.Int("confidence")), api2.LookbackNoLimit, true)
		if err != nil {
			return xerrors.Errorf("Timeout waiting for withdrawal message %s", wait.Message)
		}

		if wait.Receipt.ExitCode.IsError() {
			return xerrors.Errorf("Failed to execute withdrawal message %s: %w", wait.Message, wait.Receipt.ExitCode.Error())
		}

		nv, err := walletapi.StateNetworkVersion(ctx, wait.TipSet)
		if err != nil {
			return err
		}

		if nv >= network.Version14 {
			var withdrawn abi.TokenAmount
			if err := withdrawn.UnmarshalCBOR(bytes.NewReader(wait.Receipt.Return)); err != nil {
				return err
			}

			fmt.Printf("Successfully withdrew %s \n", types.FIL(withdrawn))
			if withdrawn.LessThan(amount) {
				fmt.Printf("Note that this is less than the requested amount of %s\n", types.FIL(amount))
			}
		}

		return nil
	},
}
