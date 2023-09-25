package api

import (
	"context"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/lotus/chain/wallet/key"
	"github.com/ipfs/go-cid"
)

type Gateway api.Gateway
type ShedWallet interface {
	Gateway
	CheckMessages(context.Context, []*api.MessagePrototype) ([][]api.MessageCheckStatus, error)

	WalletEncryptType(ctx context.Context, addr address.Address) (int, error)
	WalletEncrypt(ctx context.Context, addr address.Address, auth, newAuth, code, otpUrl []byte) error
	SetAuthInfo(context.Context, []byte, []byte) error
	WalletNew(context.Context, types.KeyType) (address.Address, error)
	WalletList(context.Context) ([]address.Address, error)
	WalletSign(context.Context, address.Address, []byte) (*crypto.Signature, error)
	GetWalletKey(context.Context, address.Address) (*key.Key, error)
	WalletVerify(context.Context, address.Address, []byte, *crypto.Signature) (bool, error)
	WalletDefaultAddress(context.Context) (address.Address, error)
	WalletExport(context.Context, address.Address) (*types.KeyInfo, error)
	WalletImport(context.Context, *types.KeyInfo) (address.Address, error)
	WalletImportId(context.Context, *types.KeyInfo, address.Address) (address.Address, error)
	WalletSetDefault(context.Context, address.Address) error
	// WalletBalance(context.Context, address.Address) (types.BigInt, error)
	WalletDelete(context.Context, address.Address) error
	MarketWithdraw(ctx context.Context, wallet, addr address.Address, amt types.BigInt) (cid.Cid, error)
	MarketAddBalance(ctx context.Context, wallet, addr address.Address, amt types.BigInt) (cid.Cid, error)
	MarketGetReserved(ctx context.Context, addr address.Address) (types.BigInt, error)

	MsigAddApprove(context.Context, address.Address, address.Address, uint64, address.Address, address.Address, bool) (*api.MessagePrototype, error)

	MsigAddPropose(context.Context, address.Address, address.Address, address.Address, bool) (*api.MessagePrototype, error)

	MpoolPushMessage(ctx context.Context, msg *types.Message, spec *api.MessageSendSpec) (*types.SignedMessage, error)

	WalletSignMessage(context.Context, address.Address, *types.Message) (*types.SignedMessage, error)

	MsigRemoveSigner(ctx context.Context, msig address.Address, proposer address.Address, toRemove address.Address, decrease bool) (*api.MessagePrototype, error)

	MsigCreate(context.Context, uint64, []address.Address, abi.ChainEpoch, types.BigInt, address.Address, types.BigInt) (*api.MessagePrototype, error)

	MsigApprove(ctx context.Context, msig address.Address, txID uint64, src address.Address) (*api.MessagePrototype, error)
	MsigCancel(context.Context, address.Address, uint64, address.Address) (*api.MessagePrototype, error)
	MsigCancelTxnHash(context.Context, address.Address, uint64, address.Address, types.BigInt, address.Address, uint64, []byte) (*api.MessagePrototype, error)

	MsigApproveTxnHash(context.Context, address.Address, uint64, address.Address, address.Address, types.BigInt, address.Address, uint64, []byte) (*api.MessagePrototype, error)
	MsigPropose(context.Context, address.Address, address.Address, types.BigInt, address.Address, uint64, []byte) (*api.MessagePrototype, error)
	MsigSwapCancel(context.Context, address.Address, address.Address, uint64, address.Address, address.Address) (*api.MessagePrototype, error)

	MsigSwapPropose(context.Context, address.Address, address.Address, address.Address, address.Address) (*api.MessagePrototype, error)
	MsigSwapApprove(context.Context, address.Address, address.Address, uint64, address.Address, address.Address, address.Address) (*api.MessagePrototype, error)
	MsigAddCancel(context.Context, address.Address, address.Address, uint64, address.Address, bool) (*api.MessagePrototype, error)
	BeneficiaryWithdrawBalance(ctx context.Context, maddr address.Address, amount abi.TokenAmount) (cid.Cid, error)
	ActorWithdrawBalance(ctx context.Context, maddr address.Address, amount abi.TokenAmount) (cid.Cid, error)
}
