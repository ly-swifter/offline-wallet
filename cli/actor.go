package cli

import (
	"fmt"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/big"
	"github.com/filecoin-project/go-state-types/builtin"
	api2 "github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/build"
	"github.com/filecoin-project/lotus/chain/actors"
	"github.com/filecoin-project/lotus/chain/types"
	lcli "github.com/filecoin-project/lotus/cli"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
)

var ActorSetOwnerCmd = &cli.Command{
	Name:      "set-owner",
	Usage:     "Set owner address (this command should be invoked twice, first with the old owner as the senderAddress, and then with the new owner)",
	ArgsUsage: "[MinerAddr] [newOwnerAddress senderAddress]",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "really-do-it",
			Usage: "Actually send transaction performing the action",
			Value: false,
		},
	},
	Action: func(cctx *cli.Context) error {
		if !cctx.Bool("really-do-it") {
			fmt.Println("Pass --really-do-it to actually execute this action")
			return nil
		}

		if cctx.NArg() != 3 {
			return fmt.Errorf("usage: set-owner <MinerAddr> <newOwnerAddress> <senderAddress> must pass new owner address and sender address")
		}

		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close() //nolint:errcheck

		api := srv.WalletAPI()

		ctx := lcli.ReqContext(cctx)

		maddr, err := address.NewFromString(cctx.Args().First())
		if err != nil {
			return err
		}

		na, err := address.NewFromString(cctx.Args().Get(1))
		if err != nil {
			return err
		}

		newAddrId, err := api.StateLookupID(ctx, na, types.EmptyTSK)
		if err != nil {
			return err
		}

		fa, err := address.NewFromString(cctx.Args().Get(2))
		if err != nil {
			return err
		}

		fromAddrId, err := api.StateLookupID(ctx, fa, types.EmptyTSK)
		if err != nil {
			return err
		}

		mi, err := api.StateMinerInfo(ctx, maddr, types.EmptyTSK)
		if err != nil {
			return err
		}

		if fromAddrId != mi.Owner && fromAddrId != newAddrId {
			return xerrors.New("from address must either be the old owner or the new owner")
		}

		sp, err := actors.SerializeParams(&newAddrId)
		if err != nil {
			return xerrors.Errorf("serializing params: %w", err)
		}

		smsg, err := InteractiveSend(ctx, cctx, srv, &api2.MessagePrototype{Message: types.Message{
			From:   fromAddrId,
			To:     maddr,
			Method: builtin.MethodsMiner.ChangeOwnerAddress,
			Value:  big.Zero(),
			Params: sp,
		}})
		if err != nil {
			return err
		}

		fmt.Println("Message CID:", smsg.Cid())

		// wait for it to get mined into a block
		wait, err := api.StateWaitMsg(ctx, smsg.Cid(), build.MessageConfidence, api2.LookbackNoLimit, true)
		if err != nil {
			return err
		}

		// check it executed successfully
		if wait.Receipt.ExitCode != 0 {
			fmt.Println("owner change failed!")
			return err
		}

		fmt.Println("message succeeded!")

		return nil
	},
}
