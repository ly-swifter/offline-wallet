package cli

import (
	"math/big"

	"github.com/filecoin-project/lily/lens/util"
	"github.com/filecoin-project/lotus/build"
	"github.com/filecoin-project/lotus/chain/consensus"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/lotus/node/repo"
	glifcmd "github.com/glifio/cli/cmd"
	"github.com/glifio/go-pools/constants"
	"github.com/glifio/go-pools/deploy"
	"github.com/glifio/go-pools/sdk"
	gliftypes "github.com/glifio/go-pools/types"
	logging "github.com/ipfs/go-log/v2"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	build2 "offline-wallet/build"
	wallet2 "offline-wallet/chain/wallet"
	swallet "offline-wallet/wallet"
)

var log = logging.Logger("cli")

func GetWalletAPI(ctx *cli.Context) (ServicesAPI, error) {
	var isTest bool = true
	networkName := build2.NetworkName
	if networkName == "main" {
		isTest = false
	}

	isOffline := ctx.Bool("offline")
	lr, ks, err := openRepo(ctx)
	if err != nil {
		return nil, err
	}

	lw, err := wallet2.NewWallet(ks)
	if err != nil {
		return nil, err
	}

	ds, err := lr.Datastore(ctx.Context, "/metadata")
	if err != nil {
		return nil, err
	}

	if isOffline {
		return &ServicesImpl{
			api: swallet.NewShedWallet(lw, nil, ds),
			closer: func() {
				lr.Close()
			},
		}, nil
	}

	var extern gliftypes.Extern
	var chainID uint64
	if isTest {
		chainID = constants.CalibnetChainID
		extern = deploy.TestExtern
	} else {
		chainID = constants.MainnetChainID
		extern = deploy.Extern
	}

	poolsSDK, err := sdk.New(ctx.Context, big.NewInt(int64(chainID)), extern)
	if err != nil {
		return nil, xerrors.Errorf("Failed to initialize pools sdk %s", err)
	}

	glifcmd.PoolsSDK = poolsSDK
	gateway, closer, err := poolsSDK.Extern().ConnectLotusClient()
	if err != nil {
		return nil, err
	}

	netw, err := gateway.StateNetworkName(ctx.Context)
	if err != nil {
		return nil, err
	}

	build.UseNetworkBundle(string(netw))
	util.ActorRegistry = consensus.NewActorRegistry()

	finalCloser := func() {
		closer()
		lr.Close()
	}

	return &ServicesImpl{
		PoolsSDK: poolsSDK,
		api:      swallet.NewShedWallet(lw, gateway, ds),
		closer:   finalCloser,
	}, nil
}

func openRepo(cctx *cli.Context) (repo.LockedRepo, types.KeyStore, error) {
	repoPath := cctx.String("repo")
	r, err := repo.NewFS(repoPath)
	if err != nil {
		return nil, nil, err
	}

	ok, err := r.Exists()
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		if err := r.Init(repo.Wallet); err != nil {
			return nil, nil, err
		}
	}

	lr, err := r.Lock(repo.Wallet)
	if err != nil {
		return nil, nil, err
	}

	ks, err := lr.KeyStore()
	if err != nil {
		return nil, nil, err
	}

	return lr, ks, nil
}
