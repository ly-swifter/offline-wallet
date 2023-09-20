package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"offline-wallet/wallet"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethereumtypes "github.com/ethereum/go-ethereum/core/types"
	builtintypes "github.com/filecoin-project/go-state-types/builtin"
	"github.com/filecoin-project/lotus/chain/types/ethtypes"

	apisafe "offline-wallet/api"
	"reflect"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/filecoin-project/lotus/chain/messagesigner"
	gliftypes "github.com/glifio/go-pools/types"
	"github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
	"golang.org/x/xerrors"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"

	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/chain/consensus"
	"github.com/filecoin-project/lotus/chain/types"
)

//go:generate go run github.com/golang/mock/mockgen -destination=servicesmock_test.go -package=cli -self_package github.com/filecoin-project/lotus/cli . ServicesAPI

type ServicesAPI interface {
	gliftypes.PoolsSDK
	WalletAPI() apisafe.ShedWallet

	GetBaseFee(ctx context.Context) (abi.TokenAmount, error)

	// MessageForSend creates a prototype of a message based on SendParams
	MessageForSend(ctx context.Context, params SendParams) (*api.MessagePrototype, error)

	// DecodeTypedParamsFromJSON takes in information needed to identify a method and converts JSON
	// parameters to bytes of their CBOR encoding
	DecodeTypedParamsFromJSON(ctx context.Context, to address.Address, method abi.MethodNum, paramstr string) ([]byte, error)

	//RunChecksForPrototype(ctx context.Context, prototype *api.MessagePrototype) ([][]api.MessageCheckStatus, error)

	// PublishMessage takes in a message prototype and publishes it
	// before publishing the message, it runs checks on the node, message and mpool to verify that
	// message is valid and won't be stuck.
	// if `force` is true, it skips the checks
	PublishMessage(ctx context.Context, prototype *api.MessagePrototype, force bool, spec *api.MessageSendSpec) (*types.SignedMessage, [][]api.MessageCheckStatus, error)

	// Close ends the session of services and disconnects from RPC, using Services after Close is called
	// most likely will result in an error
	// Should not be called concurrently
	Close() error

	WaitEthereumTx(ctx context.Context, transaction *ethereumtypes.Transaction) (*ethereumtypes.Receipt, error)
}

type ServicesImpl struct {
	gliftypes.PoolsSDK
	signer messagesigner.MessageSigner
	api    apisafe.ShedWallet
	closer func()
}

func (s *ServicesImpl) WaitEthereumTx(ctx context.Context, tx *ethereumtypes.Transaction) (*ethereumtypes.Receipt, error) {
	txData, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	ethTx, err := ethtypes.ParseEthTxArgs(txData)
	if err != nil {
		return nil, err
	}
	sm, err := ToSignedMessage(ethTx)
	if err != nil {
		return nil, err
	}

	wallet.PrintMessageInfo(ctx, &sm.Message, s.api)

	_, err = s.api.StateWaitMsg(ctx, sm.Cid(), 3, api.LookbackNoLimit, true)
	if err != nil {
		return nil, xerrors.Errorf("state wait msg  failed: %w", err)
	}
	ethTxHash, err := ethTx.TxHash()
	if err != nil {
		return nil, err
	}
	receipt, err := s.api.EthGetTransactionReceipt(ctx, ethTxHash)
	if err != nil {
		return nil, err
	}

	receiptData, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	r := new(ethereumtypes.Receipt)
	err = r.UnmarshalJSON(receiptData)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *ServicesImpl) WalletAPI() apisafe.ShedWallet {
	return s.api
}

func (s *ServicesImpl) Close() error {
	if s.closer == nil {
		return xerrors.Errorf("Services already closed")
	}
	s.closer()
	s.closer = nil
	return nil
}

func (s *ServicesImpl) GetBaseFee(ctx context.Context) (abi.TokenAmount, error) {
	// not used but useful

	ts, err := s.api.ChainHead(ctx)
	if err != nil {
		return abi.NewTokenAmount(0), xerrors.Errorf("getting head: %w", err)
	}
	return ts.MinTicketBlock().ParentBaseFee, nil
}

func (s *ServicesImpl) DecodeTypedParamsFromJSON(ctx context.Context, to address.Address, method abi.MethodNum, paramstr string) ([]byte, error) {
	act, err := s.api.StateGetActor(ctx, to, types.EmptyTSK)
	if err != nil {
		return nil, err
	}

	methodMeta, found := consensus.NewActorRegistry().Methods[act.Code][method] // TODO: use remote map
	if !found {
		return nil, fmt.Errorf("method %d not found on actor %s", method, act.Code)
	}

	p := reflect.New(methodMeta.Params.Elem()).Interface().(cbg.CBORMarshaler)

	if err := json.Unmarshal([]byte(paramstr), p); err != nil {
		return nil, fmt.Errorf("unmarshaling input into params type: %w", err)
	}

	buf := new(bytes.Buffer)
	if err := p.MarshalCBOR(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type CheckInfo struct {
	MessageTie        cid.Cid
	CurrentMessageTie bool

	Check api.MessageCheckStatus
}

var ErrCheckFailed = fmt.Errorf("check has failed")

func (s *ServicesImpl) RunChecksForPrototype(ctx context.Context, prototype *api.MessagePrototype) ([][]api.MessageCheckStatus, error) {
	var outChecks [][]api.MessageCheckStatus
	checks, err := s.api.CheckMessages(ctx, []*api.MessagePrototype{prototype})
	if err != nil {
		return nil, xerrors.Errorf("message check: %w", err)
	}
	outChecks = append(outChecks, checks...)

	//checks, err = s.api.MpoolCheckPendingMessages(ctx, prototype.Message.From)
	//if err != nil {
	//	return nil, xerrors.Errorf("pending mpool check: %w", err)
	//}
	//outChecks = append(outChecks, checks...)

	return outChecks, nil
}

// PublishMessage modifies prototype to include gas estimation
// Errors with ErrCheckFailed if any of the checks fail
// First group of checks is related to the message prototype
func (s *ServicesImpl) PublishMessage(ctx context.Context, prototype *api.MessagePrototype, force bool, spec *api.MessageSendSpec) (*types.SignedMessage, [][]api.MessageCheckStatus, error) {

	gasedMsg, err := s.api.GasEstimateMessageGas(ctx, &prototype.Message, spec, types.EmptyTSK)
	if err != nil {
		return nil, nil, xerrors.Errorf("estimating gas: %w", err)
	}
	prototype.Message = *gasedMsg

	if !force {
		checks, err := s.RunChecksForPrototype(ctx, prototype)
		if err != nil {
			return nil, nil, xerrors.Errorf("running checks: %w", err)
		}
		for _, chks := range checks {
			for _, c := range chks {
				if !c.OK {
					return nil, checks, ErrCheckFailed
				}
			}
		}
	}

	if prototype.Message.From.Protocol() == address.Delegated {
		sm, _, err := s.publishMessage(ctx, prototype)
		if err != nil {
			return nil, nil, err
		}
		if sm != nil {
			return sm, nil, nil
		}
	}

	var sm *types.SignedMessage
	if !prototype.ValidNonce {
		prototype.Message.Nonce, err = s.api.MpoolGetNonce(ctx, prototype.Message.From)
		if err != nil {
			return nil, nil, err
		}
	}

	from := prototype.Message.From

	if from.Protocol() == address.ID {
		from, err = s.api.StateAccountKey(ctx, from, types.EmptyTSK)
		if err != nil {
			return nil, nil, err
		}
		prototype.Message.From = from
	}
	sm, err = s.api.WalletSignMessage(ctx, from, &prototype.Message)
	if err != nil {
		return nil, nil, err
	}
	_, err = s.api.MpoolPush(ctx, sm)
	if err != nil {
		return nil, nil, err
	}
	return sm, nil, nil
}

func (s *ServicesImpl) publishMessage(ctx context.Context, prototype *api.MessagePrototype) (*types.SignedMessage, [][]api.MessageCheckStatus, error) {
	var err error
	if prototype.Message.From.Protocol() == address.Delegated {
		if !prototype.ValidNonce {
			prototype.Message.Nonce, err = s.api.MpoolGetNonce(ctx, prototype.Message.From)
			if err != nil {
				return nil, nil, err
			}
		}
		chainId, err := s.api.EthChainId(ctx)
		if err != nil {
			return nil, nil, err
		}
		signer := ethereumtypes.LatestSignerForChainID(big.NewInt(int64(chainId)))

		ethClient, err := s.Extern().ConnectEthClient()
		if err != nil {
			return nil, nil, err
		}
		key, err := s.api.GetWalletKey(ctx, prototype.Message.From)
		if err != nil {
			return nil, nil, err
		}
		senderKey, err := crypto.ToECDSA(key.PrivateKey)
		if err != nil {
			return nil, nil, err
		}
		var signerTx *ethereumtypes.Transaction
		if prototype.Message.To.Protocol() == address.Delegated {

			ethTx, err := ethtypes.EthTxArgsFromUnsignedEthMessage(&prototype.Message)
			if err != nil {
				return nil, nil, err
			}

			signerTx, err = ethereumtypes.SignNewTx(senderKey, signer, &ethereumtypes.DynamicFeeTx{
				ChainID:   big.NewInt(int64(chainId)),
				Nonce:     prototype.Message.Nonce,
				GasTipCap: prototype.Message.GasPremium.Int,
				GasFeeCap: prototype.Message.GasFeeCap.Int,
				Gas:       uint64(prototype.Message.GasLimit),
				To:        (*common.Address)(ethTx.To),
				Value:     ethTx.Value.Int,
				Data:      ethTx.Input,
			})
			if err != nil {
				return nil, nil, err
			}
			err = ethClient.SendTransaction(ctx, signerTx)

			if err != nil {
				return nil, nil, err
			}

		} else if prototype.Message.To.Protocol() != address.ID {
			destination := prototype.Message.To.Bytes()

			ffAddress := common.HexToAddress("0x2B3ef6906429b580b7b2080de5CA893BC282c225")
			prototype.Message.To, err = ethtypes.EthAddress(ffAddress).ToFilecoinAddress()
			if err != nil {
				return nil, nil, err
			}
			ff, err := contract.NewFilForwarderTransactor(ffAddress, ethClient)
			if err != nil {
				return nil, nil, err
			}
			from, err := ethtypes.EthAddressFromFilecoinAddress(prototype.Message.From)
			if err != nil {
				return nil, nil, err
			}
			opts := &bind.TransactOpts{
				From:  common.Address(from),
				Nonce: big.NewInt(int64(prototype.Message.Nonce)),
				Signer: func(c common.Address, transaction *ethereumtypes.Transaction) (*ethereumtypes.Transaction, error) {
					return ethereumtypes.SignTx(transaction, signer, senderKey)
				},
				Value:     prototype.Message.Value.Int,
				GasTipCap: prototype.Message.GasPremium.Int,
				GasFeeCap: prototype.Message.GasFeeCap.Int,
				GasLimit:  uint64(prototype.Message.GasLimit),
				Context:   ctx,
				NoSend:    true,
			}
			signerTx, err = ff.Forward(opts, destination)
			if err != nil {
				return nil, nil, err
			}
			signerTxData, err := signerTx.MarshalBinary()
			if err != nil {
				return nil, nil, err
			}
			ethTxArgs, err := ethtypes.ParseEthTxArgs(signerTxData)
			if err != nil {
				return nil, nil, err
			}
			sm, err := ToSignedMessage(ethTxArgs)
			if err != nil {
				return nil, nil, err
			}
			result, err := s.api.StateCall(ctx, &sm.Message, types.EmptyTSK)
			if err != nil {
				return nil, nil, err
			}
			opts.GasLimit = result.GasCost.GasUsed.Uint64()
			opts.NoSend = false
			signerTx, err = ff.Forward(opts, destination)
			if err != nil {
				return nil, nil, err
			}
		}

		if signerTx != nil {
			signerTxData, err := signerTx.MarshalBinary()
			if err != nil {
				return nil, nil, err
			}

			ethTxArgs, err := ethtypes.ParseEthTxArgs(signerTxData)
			sm, err := ToSignedMessage(ethTxArgs)
			if err != nil {
				return nil, nil, err
			}
			return sm, nil, nil
		}

	}
	return nil, nil, nil
}

type SendParams struct {
	To   address.Address
	From address.Address
	Val  abi.TokenAmount

	GasPremium *abi.TokenAmount
	GasFeeCap  *abi.TokenAmount
	GasLimit   *int64

	Nonce  *uint64
	Method abi.MethodNum
	Params []byte
}

func (s *ServicesImpl) MessageForSend(ctx context.Context, params SendParams) (*api.MessagePrototype, error) {
	if params.From == address.Undef {
		defaddr, err := s.api.WalletDefaultAddress(ctx)
		if err != nil {
			return nil, err
		}
		params.From = defaddr
	}

	msg := types.Message{
		From:  params.From,
		To:    params.To,
		Value: params.Val,

		Method: params.Method,
		Params: params.Params,
	}

	if params.GasPremium != nil {
		msg.GasPremium = *params.GasPremium
	} else {
		msg.GasPremium = types.NewInt(0)
	}
	if params.GasFeeCap != nil {
		msg.GasFeeCap = *params.GasFeeCap
	} else {
		msg.GasFeeCap = types.NewInt(0)
	}
	if params.GasLimit != nil {
		msg.GasLimit = *params.GasLimit
	} else {
		msg.GasLimit = 0
	}
	validNonce := false
	if params.Nonce != nil {
		msg.Nonce = *params.Nonce
		validNonce = true
	}

	prototype := &api.MessagePrototype{
		Message:    msg,
		ValidNonce: validNonce,
	}
	return prototype, nil
}

func ToUnsignedMessage(tx *ethtypes.EthTxArgs, from address.Address) (*types.Message, error) {
	var err error
	var params []byte
	if len(tx.Input) > 0 {
		buf := new(bytes.Buffer)
		if err = cbg.WriteByteArray(buf, tx.Input); err != nil {
			return nil, xerrors.Errorf("failed to write input args: %w", err)
		}
		params = buf.Bytes()
	}

	var to address.Address
	var method abi.MethodNum
	// nil indicates the EAM, only CreateExternal is allowed
	if tx.To == nil {
		method = builtintypes.MethodsEAM.CreateExternal
		to = builtintypes.EthereumAddressManagerActorAddr
	} else {
		method = builtintypes.MethodsEVM.InvokeContract
		to, err = tx.To.ToFilecoinAddress()
		if err != nil {
			return nil, xerrors.Errorf("failed to convert To into filecoin addr: %w", err)
		}
	}

	return &types.Message{
		Version:    0,
		To:         to,
		From:       from,
		Nonce:      uint64(tx.Nonce),
		Value:      tx.Value,
		GasLimit:   int64(tx.GasLimit),
		GasFeeCap:  tx.MaxFeePerGas,
		GasPremium: tx.MaxPriorityFeePerGas,
		Method:     method,
		Params:     params,
	}, nil
}

func ToSignedMessage(tx *ethtypes.EthTxArgs) (*types.SignedMessage, error) {
	from, err := tx.Sender()
	if err != nil {
		return nil, xerrors.Errorf("failed to calculate sender: %w", err)
	}

	unsignedMsg, err := ToUnsignedMessage(tx, from)
	if err != nil {
		return nil, xerrors.Errorf("failed to convert to unsigned msg: %w", err)
	}

	siggy, err := tx.Signature()
	if err != nil {
		return nil, xerrors.Errorf("failed to calculate signature: %w", err)
	}

	return &types.SignedMessage{
		Message:   *unsignedMsg,
		Signature: *siggy,
	}, nil
}
