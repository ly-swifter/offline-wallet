package wallet

import (
	"context"
	"encoding/json"
	wallet2 "offline-wallet/chain/wallet"
	"strings"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/big"
	builtintypes "github.com/filecoin-project/go-state-types/builtin"
	minertypes "github.com/filecoin-project/go-state-types/builtin/v11/miner"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/chain/actors"
	marketactor "github.com/filecoin-project/lotus/chain/actors/builtin/market"
	"github.com/filecoin-project/lotus/chain/messagepool"
	"github.com/filecoin-project/lotus/chain/messagesigner"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/lotus/chain/wallet/key"
	"github.com/filecoin-project/lotus/lib/sigs"
	"github.com/google/uuid"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/go-datastore"
	logging "github.com/ipfs/go-log/v2"
	"golang.org/x/xerrors"
)

var log = logging.Logger("wallet")

type ShedWallet struct {
	LocalWallet *wallet2.LocalWallet
	*MsigAPI
	MessageSigner *messagesigner.MessageSigner
}

func (sw *ShedWallet) withdrawBalance(ctx context.Context, maddr address.Address, amount abi.TokenAmount, fromOwner bool) (cid.Cid, error) {

	params, serr := actors.SerializeParams(&minertypes.WithdrawBalanceParams{
		AmountRequested: amount,
	})
	if serr != nil {
		return cid.Undef, serr
	}

	mi, err := sw.StateMinerInfo(ctx, maddr, types.EmptyTSK)
	if err != nil {
		return cid.Undef, xerrors.Errorf("Error getting miner's owner address: %w", err)
	}

	var sender address.Address
	if fromOwner {
		sender = mi.Owner
	} else {
		sender = mi.Beneficiary
	}

	smsg, err := sw.MpoolPushMessage(ctx, &types.Message{
		To:     maddr,
		From:   sender,
		Value:  types.NewInt(0),
		Method: builtintypes.MethodsMiner.WithdrawBalance,
		Params: params,
	}, &api.MessageSendSpec{})
	if err != nil {
		return cid.Undef, err
	}

	return smsg.Cid(), nil
}

func (sw *ShedWallet) BeneficiaryWithdrawBalance(ctx context.Context, maddr address.Address, amount abi.TokenAmount) (cid.Cid, error) {
	return sw.withdrawBalance(ctx, maddr, amount, false)
}

func (sw *ShedWallet) ActorWithdrawBalance(ctx context.Context, maddr address.Address, amount abi.TokenAmount) (cid.Cid, error) {
	return sw.withdrawBalance(ctx, maddr, amount, true)
}

func (sw *ShedWallet) WalletEncrypt(ctx context.Context, addr address.Address, passwd []byte, newPasswd []byte, code []byte, optUrl []byte) error {
	return sw.LocalWallet.WalletEncrypt(ctx, addr, passwd, newPasswd, code, optUrl)
}

func (sw *ShedWallet) WalletEncryptType(ctx context.Context, addr address.Address) (int, error) {
	return sw.LocalWallet.WalletEncryptType(ctx, addr)
}

func (sw *ShedWallet) SetAuthInfo(ctx context.Context, auth []byte, code []byte) error {
	return sw.LocalWallet.SetAuth(ctx, auth, code)
}

func NewShedWallet(lw *wallet2.LocalWallet, gateway api.Gateway, ds datastore.Batching) *ShedWallet {
	w := &ShedWallet{LocalWallet: lw, MsigAPI: &MsigAPI{Gateway: gateway}}

	w.MessageSigner = messagesigner.NewMessageSigner(lw, w, ds)
	return w
}

func (sw *ShedWallet) GetWalletKey(ctx context.Context, keyAddr address.Address) (*key.Key, error) {
	return sw.LocalWallet.GetWalletKey(ctx, keyAddr)
}
func (sw *ShedWallet) WalletSign(ctx context.Context, keyAddr address.Address, msg []byte) (*crypto.Signature, error) {
	return sw.LocalWallet.WalletSign(ctx, keyAddr, msg, api.MsgMeta{
		Type: api.MTUnknown,
	})
}

// func (sw *ShedWallet) WalletBalance(ctx context.Context, keyAddr address.Address) (types.BigInt, error) {
// 	return sw.LocalWallet.walletBalance(ctx, keyAddr)
// }

func (sw *ShedWallet) WalletNew(ctx context.Context, keyType types.KeyType) (address.Address, error) {
	return sw.LocalWallet.WalletNew(ctx, keyType)
}

func (sw *ShedWallet) WalletHas(ctx context.Context, a address.Address) (bool, error) {
	return sw.LocalWallet.WalletHas(ctx, a)
}

func (sw *ShedWallet) WalletList(ctx context.Context) ([]address.Address, error) {
	return sw.LocalWallet.WalletList(ctx)
}

// func (sw *ShedWallet) WalletExport(ctx context.Context, a address.Address) (*types.KeyInfo, error) {
// 	return sw.LocalWallet.WalletExport(ctx, a)
// }

func (sw *ShedWallet) WalletImport(ctx context.Context, info *types.KeyInfo) (address.Address, error) {
	return sw.LocalWallet.WalletImport(ctx, info)
}

func (sw *ShedWallet) WalletImportId(ctx context.Context, info *types.KeyInfo, id address.Address) (address.Address, error) {
	return sw.LocalWallet.WalletImportId(ctx, info, id)
}

func (sw *ShedWallet) WalletDelete(ctx context.Context, a address.Address) error {
	return sw.LocalWallet.WalletDelete(ctx, a)
}

func (sw *ShedWallet) MarketGetReserved(ctx context.Context, addr address.Address) (types.BigInt, error) {
	return types.NewInt(0), xerrors.Errorf("not impl")
}
func (sw *ShedWallet) MarketReserveFunds(ctx context.Context, wallet address.Address, addr address.Address, amt types.BigInt) (cid.Cid, error) {
	return cid.Undef, xerrors.Errorf("not impl")
}
func (sw *ShedWallet) MarketWithdraw(ctx context.Context, wallet, addr address.Address, amt types.BigInt) (cid.Cid, error) {
	return cid.Undef, xerrors.Errorf("not impl")
}
func (sw *ShedWallet) MarketAddBalance(ctx context.Context, wallet, addr address.Address, amt types.BigInt) (cid.Cid, error) {
	params, err := actors.SerializeParams(&addr)
	if err != nil {
		return cid.Undef, err
	}

	smsg, aerr := sw.MpoolPushMessage(ctx, &types.Message{
		To:     marketactor.Address,
		From:   wallet,
		Value:  amt,
		Method: marketactor.Methods.AddBalance,
		Params: params,
	}, nil)

	if aerr != nil {
		return cid.Undef, aerr
	}

	return smsg.Cid(), nil
}

func (sw *ShedWallet) WalletSetDefault(ctx context.Context, addr address.Address) error {
	return sw.LocalWallet.SetDefault(addr)
}

func (sw *ShedWallet) WalletDefaultAddress(ctx context.Context) (address.Address, error) {
	return sw.LocalWallet.GetDefault()
}

func (sw *ShedWallet) WalletVerify(ctx context.Context, k address.Address, msg []byte, sig *crypto.Signature) (bool, error) {
	return sigs.Verify(sig, k, msg) == nil, nil
}
func (sw *ShedWallet) MpoolPushMessage(ctx context.Context, msg *types.Message, spec *api.MessageSendSpec) (*types.SignedMessage, error) {
	cp := *msg
	msg = &cp
	inMsg := *msg

	// Generate spec and uuid if not available in the message
	if spec == nil {
		spec = &api.MessageSendSpec{
			MsgUuid: uuid.New(),
		}
	} else if (spec.MsgUuid == uuid.UUID{}) {
		spec.MsgUuid = uuid.New()
	} else {
		// Check if this uuid has already been processed. Ignore if uuid is not populated
		signedMessage, err := sw.MessageSigner.GetSignedMessage(ctx, spec.MsgUuid)
		if err == nil {
			log.Warnf("Message already processed. cid=%s", signedMessage.Cid())
			return signedMessage, nil
		}
	}

	msg, err := sw.GasEstimateMessageGas(ctx, msg, spec, types.EmptyTSK)
	if err != nil {
		return nil, xerrors.Errorf("GasEstimateMessageGas error: %w", err)
	}

	if msg.GasPremium.GreaterThan(msg.GasFeeCap) {
		inJson, _ := json.Marshal(inMsg)
		outJson, _ := json.Marshal(msg)
		return nil, xerrors.Errorf("After estimation, GasPremium is greater than GasFeeCap, inmsg: %s, outmsg: %s", inJson, outJson)
	}

	b, err := sw.WalletBalance(ctx, msg.From)
	if err != nil {
		return nil, xerrors.Errorf("mpool push: getting origin balance: %w", err)
	}

	requiredFunds := big.Add(msg.Value, msg.RequiredFunds())
	if b.LessThan(requiredFunds) {
		return nil, xerrors.Errorf("mpool push: not enough funds: %s < %s", b, requiredFunds)
	}

	fromA, err := sw.StateAccountKey(ctx, msg.From, types.EmptyTSK)
	if err != nil {
		return nil, err
	}

	if msg.From.Protocol() == address.ID {
		log.Warnf("Push from ID address (%s), adjusting to %s", msg.From, fromA)
		msg.From = fromA
	}

	signedMsg, err := sw.MessageSigner.SignMessage(ctx, msg, spec, func(message *types.SignedMessage) error {
		_, err = sw.Gateway.MpoolPush(ctx, message)
		if err != nil {
			return xerrors.Errorf("mpool push: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = sw.MessageSigner.StoreSignedMessage(ctx, spec.MsgUuid, signedMsg)
	if err != nil {
		return nil, err
	}
	return signedMsg, nil
}

func (sw *ShedWallet) WalletSignMessage(ctx context.Context, a address.Address, msg *types.Message) (*types.SignedMessage, error) {
	sb, err := messagesigner.SigningBytes(msg, msg.From.Protocol())
	if err != nil {
		return nil, err
	}
	mb, err := msg.ToStorageBlock()
	if err != nil {
		return nil, xerrors.Errorf("serializing message: %w", err)
	}

	sig, err := sw.LocalWallet.WalletSign(ctx, a, sb, api.MsgMeta{
		Type:  api.MTChainMsg,
		Extra: mb.RawData(),
	})
	if err != nil {
		return nil, err
	}
	// Callback with the signed message
	smsg := &types.SignedMessage{
		Message:   *msg,
		Signature: *sig,
	}
	return smsg, nil
}

// GetNonce gets the nonce from current chain head.
func (sw *ShedWallet) GetNonce(ctx context.Context, addr address.Address, tsk types.TipSetKey) (uint64, error) {
	var err error
	var ts *types.TipSet
	if tsk == types.EmptyTSK {
		// we need consistent tsk
		ts, err = sw.Gateway.ChainHead(ctx)
		if err != nil {
			return 0, xerrors.Errorf("getting head: %w", err)
		}
		tsk = ts.Key()
	} else {
		ts, err = sw.Gateway.ChainGetTipSet(ctx, tsk)
		if err != nil {
			return 0, xerrors.Errorf("getting tipset: %w", err)
		}
	}

	keyAddr := addr

	if addr.Protocol() == address.ID {
		// make sure we have a key address so we can compare with messages
		keyAddr, err = sw.Gateway.StateAccountKey(ctx, addr, tsk)
		if err != nil {
			return 0, xerrors.Errorf("getting account key: %w", err)
		}
	} else {
		addr, err = sw.Gateway.StateLookupID(ctx, addr, types.EmptyTSK)
		if err != nil {
			log.Infof("failed to look up id addr for %s: %w", addr, err)
			addr = address.Undef
		}
	}

	// Load the last nonce from the state, if it exists.
	highestNonce := uint64(0)
	act, err := sw.Gateway.StateGetActor(ctx, keyAddr, ts.Key())
	if err != nil {
		if strings.Contains(err.Error(), types.ErrActorNotFound.Error()) {
			return 0, xerrors.Errorf("getting actor converted: %w", types.ErrActorNotFound)
		}
		return 0, xerrors.Errorf("getting actor: %w", err)
	}
	highestNonce = act.Nonce

	apply := func(msg *types.Message) {
		if msg.From != addr && msg.From != keyAddr {
			return
		}
		if msg.Nonce == highestNonce {
			highestNonce = msg.Nonce + 1
		}
	}

	for _, b := range ts.Blocks() {
		msgs, err := sw.Gateway.ChainGetBlockMessages(ctx, b.Cid())
		if err != nil {
			return 0, xerrors.Errorf("getting block messages: %w", err)
		}
		if keyAddr.Protocol() == address.BLS {
			for _, m := range msgs.BlsMessages {
				apply(m)
			}
		} else {
			for _, sm := range msgs.SecpkMessages {
				apply(&sm.Message)
			}
		}
	}
	return highestNonce, nil
}

func (sw *ShedWallet) GetActor(ctx context.Context, addr address.Address, tsk types.TipSetKey) (*types.Actor, error) {
	act, err := sw.Gateway.StateGetActor(ctx, addr, tsk)
	if err != nil {
		return nil, xerrors.Errorf("calling StateGetActor: %w", err)
	}

	return act, nil
}

var _ messagepool.MpoolNonceAPI = (*ShedWallet)(nil)
