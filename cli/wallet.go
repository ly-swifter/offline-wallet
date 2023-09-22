package cli

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	wallet "offline-wallet/chain/wallet"

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
	cli2 "github.com/filecoin-project/lotus/cli"
	cliutil "github.com/filecoin-project/lotus/cli/util"
	"github.com/filecoin-project/lotus/lib/tablewriter"
	"github.com/llifezou/hdwallet"
	"github.com/pquerna/otp"
	"github.com/tyler-smith/go-bip39"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
	"golang.org/x/xerrors"
)

var WalletCmd = &cli.Command{
	Name:  "wallet",
	Usage: "Manage wallet",
	Subcommands: []*cli.Command{
		// walletEncrypt,
		walletNew,
		walletList,
		walletBalance,
		walletExport,
		walletImport,
		walletGenerateMnemonic,
		walletImportMnemonic,
		walletGetDefault,
		walletSetDefault,
		walletSign,
		walletVerify,
		walletDelete,
		// walletMarket,
	},
}

var walletGenerateMnemonic = &cli.Command{
	Name:  "generateMnemonic",
	Usage: "generate mnemonic words",
	Action: func(cctx *cli.Context) error {
		_ = cli2.ReqContext(cctx)

		mnemonic, err := hdwallet.NewMnemonic(hdwallet.Mnemonic24)
		if err != nil {
			return err
		}

		fmt.Printf("mnemonic: %s\n", mnemonic)
		return nil
	},
}

var walletImportMnemonic = &cli.Command{
	Name:      "importMnemonic",
	Usage:     "import mnemonic words",
	ArgsUsage: "[<path> (optional, will read from stdin if omitted)]",
	Flags: []cli.Flag{
		// &cli.StringFlag{
		// 	Name:  "password",
		// 	Usage: "this is the 10 characters password for shuffling the origin private key",
		// 	Value: "",
		// },
		&cli.BoolFlag{
			Name:  "as-default",
			Usage: "import the given key as your new default key",
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

		walletapi := api.WalletAPI()
		// defer closer()

		ctx := cli2.ReqContext(cctx)

		var inpdata []byte
		var private []byte
		if !cctx.Args().Present() || cctx.Args().First() == "-" {
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Print("Enter private key(not display in the terminal): ")

				sigCh := make(chan os.Signal, 1)
				// Notify the channel when SIGINT is received
				signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

				go func() {
					<-sigCh
					fmt.Println("\nInterrupt signal received. Exiting...")
					os.Exit(1)
				}()

				inpdata, err = term.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return err
				}

				fmt.Println()
				fmt.Printf("inpdata: %s\n", string(inpdata))
				fmt.Println()

				mnemonic := strings.TrimSpace(string(inpdata))

				// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
				seed := bip39.NewSeed(mnemonic, "")
				fmt.Printf("seed: %s", hex.EncodeToString(seed))

				pri, err := hdwallet.GetExtendSeedFromPath(hdwallet.FilPath(0), seed)
				if err != nil {
					return err
				}

				private = pri
			}
		}

		fmt.Println()
		fmt.Println("private: ", private)

		var oriKi types.KeyInfo = types.KeyInfo{
			Type:       types.KTSecp256k1,
			PrivateKey: private,
		}

		// pubKey, err := sigs.ToPublic(ActSigType(oriKi.Type), oriKi.PrivateKey)
		// if err != nil {
		// 	return err
		// }

		// addr, err := address.NewSecp256k1Address(pubKey)
		// if err != nil {
		// 	return err
		// }

		// idaddr, err := walletapi.StateLookupID(ctx, addr, types.EmptyTSK)
		// if err != nil {
		// 	return err
		// }

		// fmt.Println()
		// fmt.Println("idaddr: ", idaddr)

		// mix := shuffleBytes(private, cctx.String("password"))
		// fmt.Println()
		// fmt.Println("mix: ", mix)

		// unmix := unshuffleBytes(mix, cctx.String("password"))
		// fmt.Println("unmix: ", unmix)
		// fmt.Println()

		// var ki types.KeyInfo = types.KeyInfo{
		// 	Type:       types.KTSecp256k1,
		// 	PrivateKey: mix,
		// }

		// fmt.Println()
		// fmt.Printf("import ki: %+v\n", oriKi)

		addr, err := walletapi.WalletImport(ctx, &oriKi)
		if err != nil {
			return err
		}

		// addr, err = walletapi.WalletImportId(ctx, &oriKi, idaddr)
		// if err != nil {
		// 	return err
		// }

		if cctx.Bool("as-default") {
			if err := walletapi.WalletSetDefault(ctx, addr); err != nil {
				return fmt.Errorf("failed to set default key: %w", err)
			}
		}

		fmt.Printf("imported key %s successfully!\n", addr)
		return nil
	},
}

func ActSigType(typ types.KeyType) crypto.SigType {
	switch typ {
	case types.KTBLS:
		return crypto.SigTypeBLS
	case types.KTSecp256k1:
		return crypto.SigTypeSecp256k1
	case types.KTDelegated:
		return crypto.SigTypeDelegated
	default:
		return crypto.SigTypeUnknown
	}
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
			Value: "hex-lotus",
		},
		&cli.BoolFlag{
			Name:  "as-default",
			Usage: "import the given key as your new default key",
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
		srv, err := GetWalletAPI(cctx)
		if err != nil {
			return err
		}
		defer srv.Close()
		api := srv.WalletAPI()

		ctx := cli2.ReqContext(cctx)

		var inpdata []byte
		if !cctx.Args().Present() || cctx.Args().First() == "-" {
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Print("Enter private key(not display in the terminal): ")

				sigCh := make(chan os.Signal, 1)
				// Notify the channel when SIGINT is received
				signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

				go func() {
					<-sigCh
					fmt.Println("\nInterrupt signal received. Exiting...")
					os.Exit(1)
				}()

				inpdata, err = term.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return err
				}
				fmt.Println()
			} else {
				reader := bufio.NewReader(os.Stdin)
				indata, err := reader.ReadBytes('\n')
				if err != nil {
					return err
				}
				inpdata = indata
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
		default:
			return fmt.Errorf("unrecognized format: %s", cctx.String("format"))
		}

		// pubKey, err := sigs.ToPublic(ActSigType(ki.Type), ki.PrivateKey)
		// if err != nil {
		// 	return err
		// }

		// var addr address.Address
		// if ki.Type == types.KTSecp256k1 {
		// 	addr, err = address.NewSecp256k1Address(pubKey)
		// 	if err != nil {
		// 		return err
		// 	}
		// } else if ki.Type == types.KTBLS {
		// 	addr, err = address.NewBLSAddress(pubKey)
		// 	if err != nil {
		// 		return err
		// 	}
		// }

		// fmt.Printf("NewAddress: %+v\n", addr)

		// idaddr, err := api.StateLookupID(ctx, addr, types.EmptyTSK)
		// if err != nil {
		// 	fmt.Printf("StateLookupID: %+v\n", idaddr)
		// 	return err
		// }

		addr, err := api.WalletImport(ctx, &ki)
		if err != nil {
			return err
		}

		// _, err = api.WalletImportId(ctx, &ki, idaddr)
		// if err != nil {
		// 	return err
		// }

		if cctx.Bool("as-default") {
			if err := api.WalletSetDefault(ctx, addr); err != nil {
				return fmt.Errorf("failed to set default key: %w", err)
			}
		}

		fmt.Printf("imported key %s successfully!\n", addr)
		return nil
	},
}

var walletSign = &cli.Command{
	Name:      "sign",
	Usage:     "sign a message",
	ArgsUsage: "<signing address> <hexMessage>",
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
