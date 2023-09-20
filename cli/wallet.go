package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fatih/color"
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/big"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/filecoin-project/go-state-types/network"
	api2 "github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/build"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/lotus/chain/types/ethtypes"
	"github.com/filecoin-project/lotus/chain/wallet/key"
	cli2 "github.com/filecoin-project/lotus/cli"
	cliutil "github.com/filecoin-project/lotus/cli/util"
	"github.com/filecoin-project/lotus/lib/tablewriter"
	"github.com/howeyc/gopass"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
)

var WalletCmd = &cli.Command{
	Name:  "wallet",
	Usage: "Manage wallet",
	Subcommands: []*cli.Command{
		walletEncrypt,
		walletNew,
		walletList,
		walletBalance,
		walletExport,
		walletImport,
		walletGetDefault,
		walletSetDefault,
		walletSign,
		walletVerify,
		walletDelete,
		walletMarket,
	},
}

var walletNew = &cli.Command{
	Name:      "new",
	Usage:     "Generate a new key of the given type",
	ArgsUsage: "[bls|secp256k1|delegated (default secp256k1)]",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "no-auth",
			Usage: "skip use auth",
			Value: false,
		},
	},
	Action: func(cctx *cli.Context) error {
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()
		ctx := cliutil.ReqContext(cctx)

		// afmt := NewAppFmt(cctx.App)

		t := cctx.Args().First()
		if t == "" {
			t = "secp256k1"
		}

		nk, err := api.WalletNew(ctx, types.KeyType(t))
		if err != nil {
			return err
		}

		fmt.Println(nk.String())

		return nil
	},
}

var walletList = &cli.Command{
	Name:  "list",
	Usage: "List wallet address",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "addr-only",
			Usage:   "Only print addresses",
			Aliases: []string{"a"},
		},
		&cli.BoolFlag{
			Name:    "id",
			Usage:   "Output ID addresses",
			Aliases: []string{"i"},
			Value:   true,
		},
		&cli.BoolFlag{
			Name:    "market",
			Usage:   "Output market balances",
			Aliases: []string{"m"},
			Value:   false,
		},
	},
	Action: func(cctx *cli.Context) error {
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()
		ctx := cliutil.ReqContext(cctx)

		addrs, err := api.WalletList(ctx)
		if err != nil {
			return err
		}

		// Assume an error means no default key is set
		def, _ := api.WalletDefaultAddress(ctx)

		tw := tablewriter.New(tablewriter.Col("Address"), tablewriter.Col("EthAddress"), tablewriter.Col("ID"), tablewriter.Col("Balance"), tablewriter.Col("WFIL"), tablewriter.Col("Market(Avail)"), tablewriter.Col("Market(Locked)"), tablewriter.Col("Nonce"), tablewriter.Col("Default"), tablewriter.NewLineCol("Error"))

		for _, addr := range addrs {
			encrypted, err := api.WalletEncryptType(ctx, addr)
			if err != nil {
				return err
			}
			var addrStr = ""
			if encrypted == 1 {
				addrStr = color.YellowString(addr.String())
			} else if encrypted == 2 {
				addrStr = color.GreenString(addr.String())
			} else {
				addrStr = color.RedString(addr.String())
			}
			if cctx.Bool("addr-only") {
				fmt.Println(addr.String())
			} else {
				a, err := api.StateGetActor(ctx, addr, types.EmptyTSK)
				if err != nil {
					if !strings.Contains(err.Error(), "actor not found") {

						tw.Write(map[string]interface{}{
							"Address": addrStr,
							"Error":   err,
						})
						continue
					}

					a = &types.Actor{
						Balance: big.Zero(),
					}
				}

				row := map[string]interface{}{
					"Address": addrStr,
					"Balance": types.FIL(a.Balance),
					"Nonce":   a.Nonce,
				}
				if addr == def {
					row["Default"] = "X"
				}

				if cctx.Bool("id") {
					id, err := api.StateLookupID(ctx, addr, types.EmptyTSK)
					if err != nil {
						row["ID"] = "n/a"
					} else {
						row["ID"] = id
					}
				}

				if cctx.Bool("market") {
					mbal, err := api.StateMarketBalance(ctx, addr, types.EmptyTSK)
					if err == nil {
						row["Market(Avail)"] = types.FIL(types.BigSub(mbal.Escrow, mbal.Locked))
						row["Market(Locked)"] = types.FIL(mbal.Locked)
					}
				}

				if addr.Protocol() == address.Delegated {
					ethAddress, err := ethtypes.EthAddressFromFilecoinAddress(addr)
					if err == nil {
						row["EthAddress"] = common.Address(ethAddress)
					}
					wfilBalance, err := srv.Query().WFILBalanceOf(ctx, common.Address(ethAddress))
					if err == nil {
						row["WFIL"] = fmt.Sprintf("%v WFIL", wfilBalance)
					}
				}
				tw.Write(row)
			}
		}

		if !cctx.Bool("addr-only") {
			return tw.Flush(os.Stdout)
		}

		return nil
	},
}

var walletBalance = &cli.Command{
	Name:      "balance",
	Usage:     "Get account balance",
	ArgsUsage: "[address]",
	Action: func(cctx *cli.Context) error {
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()
		ctx := cliutil.ReqContext(cctx)

		var addr address.Address
		if cctx.Args().First() != "" {
			addr, err = address.NewFromString(cctx.Args().First())
		} else {
			addr, err = api.WalletDefaultAddress(ctx)
		}
		if err != nil {
			return err
		}

		balance, err := api.WalletBalance(ctx, addr)
		if err != nil {
			return err
		}

		if balance.Equals(types.NewInt(0)) {
			fmt.Printf("%s (warning: may display 0 if chain sync in progress)\n", types.FIL(balance))
		} else {
			fmt.Printf("%s\n", types.FIL(balance))
		}

		return nil
	},
}

var walletGetDefault = &cli.Command{
	Name:  "default",
	Usage: "Get default wallet address",
	Action: func(cctx *cli.Context) error {
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()
		ctx := cliutil.ReqContext(cctx)

		addr, err := api.WalletDefaultAddress(ctx)
		if err != nil {
			return err
		}

		fmt.Printf("%s\n", addr.String())
		return nil
	},
}

var walletSetDefault = &cli.Command{
	Name:      "set-default",
	Usage:     "Set default wallet address",
	ArgsUsage: "[address]",
	Action: func(cctx *cli.Context) error {
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()
		ctx := cliutil.ReqContext(cctx)

		if cctx.NArg() != 1 {
			return IncorrectNumArgs(cctx)
		}

		addr, err := address.NewFromString(cctx.Args().First())
		if err != nil {
			return err
		}

		fmt.Println("Default address set to:", addr)
		return api.WalletSetDefault(ctx, addr)
	},
}

var walletEncrypt = &cli.Command{
	Name:      "encrypt",
	Usage:     "encrypt wallet address",
	ArgsUsage: "[address]",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name: "reset",
		},
		&cli.BoolFlag{
			Name:    "use-otp",
			Usage:   "Use One Time Password",
			Aliases: []string{"otp"},
		},
	},
	Action: func(cctx *cli.Context) error {
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()
		ctx := cliutil.ReqContext(cctx)

		if cctx.NArg() != 1 {
			return IncorrectNumArgs(cctx)
		}

		addr, err := address.NewFromString(cctx.Args().First())
		if err != nil {
			return err
		}
		var newPasswd, passwd []byte
		if cctx.Bool("reset") {
			passwd, err = PromptForAuth("old password", false, addr)
			if err != nil {
				return err
			}
			newPasswd, err = PromptForAuth("new password", true, addr)
			if err != nil {
				return err
			}
		} else {
			passwd, err = PromptForAuth("password", true, addr)
			if err != nil {
				return err
			}
		}

		encryptType, err := api.WalletEncryptType(ctx, addr)
		if err != nil {
			return err
		}
		var passcode, otpUrl []byte
		if encryptType > 0 {
			if encryptType == 2 {
				passcode, err = PromptForAuth("OTP Application Passcode", false, addr)
			}
			api.SetAuthInfo(ctx, passwd, passcode)
			_, err := api.WalletSign(ctx, addr, nil)
			if err != nil {
				fmt.Println("have not auth to update")
				return err
			}
		}
		if cctx.Bool("use-otp") {
			issuer := "filecoin." + build.NetworkBundle
			otpKey, oerr := totp.Generate(totp.GenerateOpts{
				Issuer:      issuer,
				AccountName: addr.String() + "@" + issuer,
			})
			if oerr != nil {
				return oerr
			}
			display(otpKey)

			for {
				passcode, err = PromptForAuth("OTP Application Passcode", false, addr)
				if err != nil {
					return err
				}
				valid := totp.Validate(string(passcode), otpKey.Secret())
				if !valid {
					fmt.Println("OTP Application Passcode Invalid!")
					continue
				}
				fmt.Println("OTP Application Passcode Valid!")
				otpUrl = []byte(otpKey.URL())
				break
			}
		}

		err = api.WalletEncrypt(ctx, addr, passwd, newPasswd, passcode, otpUrl)
		if err != nil {
			return err
		}
		fmt.Printf("%v encrypt success\n", addr)
		return nil
	},
}

func display(key *otp.Key) error {
	fmt.Printf("Issuer:       %s\n", key.Issuer())
	fmt.Printf("Account Name: %s\n", key.AccountName())
	fmt.Printf("Secret:       %s\n", key.Secret())
	//qrc, err := qrcode.New(key.URL())
	//if err != nil {
	//	fmt.Printf("qrcode %v", err)
	//	return err
	//}
	//if err := qrc.Save(terminal.New()); err != nil {
	//	fmt.Printf("qrcode save %v", err)
	//	return err
	//}
	fmt.Println("")
	fmt.Println("Please add your TOTP Secret to your OTP Application now!")
	fmt.Println("")
	return nil
}

var walletExport = &cli.Command{
	Name:      "export",
	Usage:     "export keys",
	ArgsUsage: "[address]",
	Action: func(cctx *cli.Context) error {
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()
		ctx := cliutil.ReqContext(cctx)

		afmt := NewAppFmt(cctx.App)

		if cctx.NArg() != 1 {
			return IncorrectNumArgs(cctx)
		}

		addr, err := address.NewFromString(cctx.Args().First())
		if err != nil {
			return err
		}

		CheckAuth(ctx, srv, addr)

		ki, err := api.WalletExport(ctx, addr)
		if err != nil {
			return err
		}

		b, err := json.Marshal(ki)
		if err != nil {
			return err
		}

		afmt.Println(hex.EncodeToString(b))
		return nil
	},
}

var walletImport = &cli.Command{
	Name:      "import",
	Usage:     "import keys",
	ArgsUsage: "[<path> (optional, will read from stdin if omitted)]",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "format",
			Usage: "specify input format for key",
			Value: "hex-lotus|hex-eth|json-lotus|gfc-json",
		},
		&cli.BoolFlag{
			Name:  "as-default",
			Usage: "import the given key as your new default key",
		},
	},
	Action: func(cctx *cli.Context) error {
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()
		ctx := cliutil.ReqContext(cctx)

		var inpdata []byte
		if !cctx.Args().Present() || cctx.Args().First() == "-" {
			inpdata, err = gopass.GetPasswdPrompt("Enter private key: ", true, os.Stdin, os.Stdout)
			if err != nil {
				return err
			}

		} else {
			fdata, err := os.ReadFile(cctx.Args().First())
			if err != nil {
				return err
			}
			inpdata = fdata
		}

		var ki types.KeyInfo
		switch cctx.String("format") {
		case "hex-lotus":
			data, err := hex.DecodeString(strings.TrimSpace(string(inpdata)))
			if err != nil {
				return err
			}

			if err := json.Unmarshal(data, &ki); err != nil {
				return err
			}
		case "json-lotus":
			if err := json.Unmarshal(inpdata, &ki); err != nil {
				return err
			}
		case "gfc-json":
			var f struct {
				KeyInfo []struct {
					PrivateKey []byte
					SigType    int
				}
			}
			if err := json.Unmarshal(inpdata, &f); err != nil {
				return xerrors.Errorf("failed to parse go-filecoin key: %s", err)
			}

			gk := f.KeyInfo[0]
			ki.PrivateKey = gk.PrivateKey
			switch gk.SigType {
			case 1:
				ki.Type = types.KTSecp256k1
			case 2:
				ki.Type = types.KTBLS
			default:
				return fmt.Errorf("unrecognized key type: %d", gk.SigType)
			}
		case "hex-eth":
			ki.Type = types.KTDelegated
			data, err := hex.DecodeString(strings.TrimSpace(string(inpdata)))
			if err != nil {
				return err
			}
			ki.PrivateKey = data
		default:
			return fmt.Errorf("unrecognized format: %s", cctx.String("format"))
		}

		addr, err := api.WalletImport(ctx, &ki)
		if err != nil {
			return err
		}

		if cctx.Bool("as-default") {
			if err := api.WalletSetDefault(ctx, addr); err != nil {
				return fmt.Errorf("failed to set default key: %w", err)
			}
		}

		if ki.Type == types.KTDelegated {
			k, err := key.NewKey(ki)
			if err != nil {
				return err
			}
			ethAddress, err := ethtypes.EthAddressFromFilecoinAddress(k.Address)
			if err != nil {
				return err
			}
			fmt.Printf("imported key (%s)%s successfully!\n", ethAddress, addr)
		} else {
			fmt.Printf("imported key %s successfully!\n", addr)
		}
		return nil
	},
}

var walletSign = &cli.Command{
	Name:      "sign",
	Usage:     "sign a message",
	ArgsUsage: "<signing address> <hexMessage>",
	Action: func(cctx *cli.Context) error {
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()
		ctx := cliutil.ReqContext(cctx)

		afmt := NewAppFmt(cctx.App)

		if cctx.NArg() != 2 {
			return IncorrectNumArgs(cctx)
		}

		addr, err := address.NewFromString(cctx.Args().First())

		if err != nil {
			return err
		}

		msg, err := hex.DecodeString(cctx.Args().Get(1))

		if err != nil {
			return err
		}

		CheckAuth(ctx, srv, addr)
		sig, err := api.WalletSign(ctx, addr, msg)

		if err != nil {
			return err
		}

		sigBytes := append([]byte{byte(sig.Type)}, sig.Data...)

		afmt.Println(hex.EncodeToString(sigBytes))
		return nil
	},
}

var walletVerify = &cli.Command{
	Name:      "verify",
	Usage:     "verify the signature of a message",
	ArgsUsage: "<signing address> <hexMessage> <signature>",
	Action: func(cctx *cli.Context) error {
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()
		ctx := cliutil.ReqContext(cctx)

		afmt := NewAppFmt(cctx.App)

		if cctx.NArg() != 3 {
			return IncorrectNumArgs(cctx)
		}

		addr, err := address.NewFromString(cctx.Args().First())

		if err != nil {
			return err
		}

		msg, err := hex.DecodeString(cctx.Args().Get(1))

		if err != nil {
			return err
		}

		sigBytes, err := hex.DecodeString(cctx.Args().Get(2))

		if err != nil {
			return err
		}

		var sig crypto.Signature
		if err := sig.UnmarshalBinary(sigBytes); err != nil {
			return err
		}

		ok, err := api.WalletVerify(ctx, addr, msg, &sig)
		if err != nil {
			return err
		}
		if ok {
			afmt.Println("valid")
			return nil
		}
		afmt.Println("invalid")
		return cli2.NewCliError("CLI Verify called with invalid signature")
	},
}

var walletDelete = &cli.Command{
	Name:      "delete",
	Usage:     "Soft delete an address from the wallet - hard deletion needed for permanent removal",
	ArgsUsage: "<address> ",
	Action: func(cctx *cli.Context) error {
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()
		ctx := cliutil.ReqContext(cctx)

		if cctx.NArg() != 1 {
			return IncorrectNumArgs(cctx)
		}

		addr, err := address.NewFromString(cctx.Args().First())
		if err != nil {
			return err
		}

		fmt.Println("Soft deleting address:", addr)
		fmt.Println("Hard deletion of the address in `~/.lotus/keystore` is needed for permanent removal")
		err = CheckAuth(ctx, srv, addr)
		if err != nil {
			return err
		}
		return api.WalletDelete(ctx, addr)
	},
}

var walletMarket = &cli.Command{
	Name:  "market",
	Usage: "Interact with market balances",
	Subcommands: []*cli.Command{
		walletMarketWithdraw,
		walletMarketAdd,
	},
}

var walletMarketWithdraw = &cli.Command{
	Name:      "withdraw",
	Usage:     "Withdraw funds from the Storage Market Actor",
	ArgsUsage: "[amount (FIL) optional, otherwise will withdraw max available]",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "wallet",
			Usage:   "Specify address to withdraw funds to, otherwise it will use the default wallet address",
			Aliases: []string{"w"},
		},
		&cli.StringFlag{
			Name:    "address",
			Usage:   "Market address to withdraw from (account or miner actor address, defaults to --wallet address)",
			Aliases: []string{"a"},
		},
		&cli.IntFlag{
			Name:  "confidence",
			Usage: "number of block confirmations to wait for",
			Value: int(build.MessageConfidence),
		},
	},
	Action: func(cctx *cli.Context) error {
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()
		ctx := cliutil.ReqContext(cctx)

		afmt := NewAppFmt(cctx.App)

		var wallet address.Address
		if cctx.String("wallet") != "" {
			wallet, err = address.NewFromString(cctx.String("wallet"))
			if err != nil {
				return xerrors.Errorf("parsing from address: %w", err)
			}
		} else {
			wallet, err = api.WalletDefaultAddress(ctx)
			if err != nil {
				return xerrors.Errorf("getting default wallet address: %w", err)
			}
		}

		addr := wallet
		if cctx.String("address") != "" {
			addr, err = address.NewFromString(cctx.String("address"))
			if err != nil {
				return xerrors.Errorf("parsing market address: %w", err)
			}
		}

		// Work out if there are enough unreserved, unlocked funds to withdraw
		bal, err := api.StateMarketBalance(ctx, addr, types.EmptyTSK)
		if err != nil {
			return xerrors.Errorf("getting market balance for address %s: %w", addr.String(), err)
		}

		reserved, err := api.MarketGetReserved(ctx, addr)
		if err != nil {
			return xerrors.Errorf("getting market reserved amount for address %s: %w", addr.String(), err)
		}

		avail := big.Subtract(big.Subtract(bal.Escrow, bal.Locked), reserved)

		notEnoughErr := func(msg string) error {
			return xerrors.Errorf("%s; "+
				"available (%s) = escrow (%s) - locked (%s) - reserved (%s)", msg, types.FIL(avail), types.FIL(bal.Escrow), types.FIL(bal.Locked), types.FIL(reserved))
		}

		if avail.IsZero() || avail.LessThan(big.Zero()) {
			avail = big.Zero()
			return notEnoughErr("no funds available to withdraw")
		}

		// Default to withdrawing all available funds
		amt := avail

		// If there was an amount argument, only withdraw that amount
		if cctx.Args().Present() {
			f, err := types.ParseFIL(cctx.Args().First())
			if err != nil {
				return xerrors.Errorf("parsing 'amount' argument: %w", err)
			}

			amt = abi.TokenAmount(f)
		}

		// Check the amount is positive
		if amt.IsZero() || amt.LessThan(big.Zero()) {
			return xerrors.Errorf("amount must be > 0")
		}

		// Check there are enough available funds
		if amt.GreaterThan(avail) {
			msg := fmt.Sprintf("can't withdraw more funds than available; requested: %s", types.FIL(amt))
			return notEnoughErr(msg)
		}

		CheckAuth(ctx, srv, addr)
		fmt.Printf("Submitting WithdrawBalance message for amount %s for address %s\n", types.FIL(amt), wallet.String())
		smsg, err := api.MarketWithdraw(ctx, wallet, addr, amt)
		if err != nil {
			return xerrors.Errorf("fund manager withdraw error: %w", err)
		}

		afmt.Printf("WithdrawBalance message cid: %s\n", smsg)

		// wait for it to get mined into a block
		wait, err := api.StateWaitMsg(ctx, smsg, uint64(cctx.Int("confidence")), api2.LookbackNoLimit, true)
		if err != nil {
			return err
		}

		// check it executed successfully
		if wait.Receipt.ExitCode.IsError() {
			afmt.Println(cctx.App.Writer, "withdrawal failed!")
			return err
		}

		nv, err := api.StateNetworkVersion(ctx, wait.TipSet)
		if err != nil {
			return err
		}

		if nv >= network.Version14 {
			var withdrawn abi.TokenAmount
			if err := withdrawn.UnmarshalCBOR(bytes.NewReader(wait.Receipt.Return)); err != nil {
				return err
			}

			afmt.Printf("Successfully withdrew %s \n", types.FIL(withdrawn))
			if withdrawn.LessThan(amt) {
				fmt.Printf("Note that this is less than the requested amount of %s \n", types.FIL(amt))
			}
		}

		return nil
	},
}

var walletMarketAdd = &cli.Command{
	Name:      "add",
	Usage:     "Add funds to the Storage Market Actor",
	ArgsUsage: "<amount>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "from",
			Usage:   "Specify address to move funds from, otherwise it will use the default wallet address",
			Aliases: []string{"f"},
		},
		&cli.StringFlag{
			Name:    "address",
			Usage:   "Market address to move funds to (account or miner actor address, defaults to --from address)",
			Aliases: []string{"a"},
		},
	},
	Action: func(cctx *cli.Context) error {
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()
		ctx := cliutil.ReqContext(cctx)

		afmt := NewAppFmt(cctx.App)

		// Get amount param
		if cctx.NArg() < 1 {
			return IncorrectNumArgs(cctx)
		}
		f, err := types.ParseFIL(cctx.Args().First())
		if err != nil {
			return xerrors.Errorf("parsing 'amount' argument: %w", err)
		}

		amt := abi.TokenAmount(f)

		// Get from param
		var from address.Address
		if cctx.String("from") != "" {
			from, err = address.NewFromString(cctx.String("from"))
			if err != nil {
				return xerrors.Errorf("parsing from address: %w", err)
			}
		} else {
			from, err = api.WalletDefaultAddress(ctx)
			if err != nil {
				return xerrors.Errorf("getting default wallet address: %w", err)
			}
		}

		// Get address param
		addr := from
		if cctx.String("address") != "" {
			addr, err = address.NewFromString(cctx.String("address"))
			if err != nil {
				return xerrors.Errorf("parsing market address: %w", err)
			}
		}

		CheckAuth(ctx, srv, addr)
		// Add balance to market actor
		fmt.Printf("Submitting Add Balance message for amount %s for address %s\n", types.FIL(amt), addr)
		smsg, err := api.MarketAddBalance(ctx, from, addr, amt)
		if err != nil {
			return xerrors.Errorf("add balance error: %w", err)
		}

		afmt.Printf("AddBalance message cid: %s\n", smsg)

		return nil
	},
}
