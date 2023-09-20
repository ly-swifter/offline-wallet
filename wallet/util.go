package wallet

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/ethereum/go-ethereum/signer/fourbyte"
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/big"
	init11 "github.com/filecoin-project/go-state-types/builtin/v11/init"
	"github.com/filecoin-project/go-state-types/builtin/v11/multisig"
	"github.com/filecoin-project/lily/lens/util"
	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/chain/actors/builtin"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/lotus/chain/types/ethtypes"
	big2 "math/big"
	"strings"
)

func PrintMessageReceiptInfo(ctx context.Context, api api.Gateway, msg *types.Message, result *api.MsgLookup) error {
	if result.Receipt.ExitCode.IsSuccess() {
		fmt.Printf("Status:\t\t%v\n", "OK")
	} else {
		fmt.Printf("Status:\t\t%v\n", result.Receipt.ExitCode.String())
	}
	fmt.Printf("Nonce:\t\t%v\n", msg.Nonce)
	if result.ReturnDec != nil {
		fmt.Printf("ReturnDec:\t\t%v\n", result.ReturnDec)
	}
	fmt.Printf("Gas Fee Cap:\t%v\n", types.FIL(msg.GasFeeCap).Short())
	fmt.Printf("Gas Premium:\t%v\n", types.FIL(msg.GasPremium).Short())
	fmt.Printf("Gas Limit:\t%v\n", msg.GasLimit)
	fmt.Printf("Gas Used:\t%v\n", result.Receipt.GasUsed)

	act, err := api.StateGetActor(ctx, msg.To, types.EmptyTSK)
	if err != nil {
		return err
	}
	returnMsg, _, err := util.ParseReturn(result.Receipt.Return, msg.Method, act.Code)
	if returnMsg != "" {
		fmt.Printf("Return:\t\t%v\n", returnMsg)
	}
	if !result.Receipt.ExitCode.IsSuccess() {
		invoke, err := api.StateCall(ctx, msg, result.TipSet)
		if err != nil {
			fmt.Printf("Error Message:\t%v\n", err)
			return nil
		}
		fmt.Printf("Error Message:\t%v\n", invoke.Error)
	}
	return nil
}
func PrintMessageInfo(ctx context.Context, msg *types.Message, api api.Gateway) error {
	act, err := api.StateGetActor(ctx, msg.To, types.EmptyTSK)
	if err != nil {
		return err
	}
	// since the message applied successfully (non-zero exitcode) its receiver must exist on chain.
	toActorCode := act.Code

	// the message applied successfully and we found its actor code, failing to parse here indicates an error.
	method, params, err := util.MethodAndParamsForMessage(msg, toActorCode)
	if err != nil {
		return err
	}

	fmt.Printf("From:\t\t%v\n", msg.From)
	fmt.Printf("To:\t\t%v\n", msg.To)
	fmt.Printf("Nonce:\t\t%v\n", msg.Nonce)
	fmt.Printf("Method:\t\t%v\n", method)
	fmt.Printf("Value:\t\t%v\n", types.FIL(msg.Value))

	if params != "" {
		p, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(params, "\"", ""))

		if err == nil && method == "InvokeContract" {
			tx, err := ethtypes.EthTxArgsFromUnsignedEthMessage(msg)
			if err != nil {
				return err
			}
			four, err := fourbyte.New()
			if err != nil {
				return err
			}
			borrowData, err := hex.DecodeString("5859117d")
			if err != nil {
				return err
			}

			four.AddSelector("borrow(uint256,((address,uint256,uint256,uint256,uint256,bytes4,uint64,bytes),uint8,bytes32,bytes32))", borrowData)
			messages := apitypes.ValidationMessages{}
			four.ValidateCallData(nil, tx.Input, &messages)
			fmt.Printf("Parameters:\n")
			for _, m := range messages.Messages {
				cc := strings.ReplaceAll(m.Message, `Transaction invokes the following method: "`, "")
				cc = strings.ReplaceAll(cc, `"`, "")
				fmt.Printf("\t %v\n", cc)
			}
		} else {
			fmt.Printf("Parameters:\t0x%v\n", hex.EncodeToString(p))
		}
	}

	if builtin.IsMultisigActor(toActorCode) {
		ParseMultisig(ctx, api, msg.To, method, params)
	}

	if method == "Exec" {
		var para init11.ExecParams
		err := json.Unmarshal([]byte(params), &para)
		if err != nil {
			fmt.Printf("Unmarshal err %v\n", err)
			return err
		}
		var p multisig.ConstructorParams

		err = p.UnmarshalCBOR(bytes.NewReader(para.ConstructorParams))
		if err != nil {
			fmt.Printf("Unmarshal err %v\n", err)
			return err
		}
		fmt.Printf("\t\tSigners:\t\t%v\n", p.Signers)
		fmt.Printf("\t\tNumApprovalsThreshold:\t%v\n", p.NumApprovalsThreshold)
		fmt.Printf("\t\tUnlockDuration:\t\t%v\n", p.UnlockDuration)
		fmt.Printf("\t\tStartEpoch:\t\t%v\n", p.StartEpoch)
	}

	return nil
}

func ParseMultisig(ctx context.Context, api api.Gateway, to address.Address, method string, params string) error {
	if method == "Propose" {
		type msgInternal struct {
			Method abi.MethodNum
			Params []byte
			To     address.Address
			Value  struct {
				Int *big2.Int
			}
		}
		var msg2 msgInternal
		err := json.Unmarshal([]byte(params), &msg2)
		if err != nil {
			fmt.Printf("Unmarshal err %v\n", err)
			return err
		}
		printInternalMessage(ctx, api, msg2.To, big.NewFromGo(msg2.Value.Int), msg2.Method, msg2.Params)
	} else if method == "Approve" {
		pending, err := api.MsigGetPending(ctx, to, types.EmptyTSK)
		if err != nil {
			fmt.Printf("MsigGetPending err %v\n", err)
			return err
		}
		var txIdParams multisig.TxnIDParams
		err = json.Unmarshal([]byte(params), &txIdParams)
		if err != nil {
			fmt.Printf("TxnIDParams Unmarshal err %v\n", err)
			return err
		}
		for _, tx := range pending {
			if multisig.TxnID(tx.ID) == txIdParams.ID {

				fmt.Printf("Propose:\n")
				fmt.Printf("\t\tApproved: %s\n", tx.Approved)
				printInternalMessage(ctx, api, tx.To, tx.Value, tx.Method, tx.Params)
			}
		}
	}

	return nil
}

func printInternalMessage(ctx context.Context, api api.Gateway, to address.Address, val abi.TokenAmount, method abi.MethodNum, params []byte) error {
	act2, err := api.StateGetActor(ctx, to, types.EmptyTSK)
	if err != nil {
		fmt.Printf("StateGetActor err %v\n", err)
		return err
	}
	// since the message applied successfully (non-zero exitcode) its receiver must exist on chain.
	toActorCode2 := act2.Code
	internal := &types.Message{
		To:     to,
		Value:  val,
		Method: method,
		Params: params,
	}
	method2, params2, err := util.MethodAndParamsForMessage(internal, toActorCode2)
	if err != nil {
		fmt.Printf("MethodAndParamsForMessage err %v\n", err)
		return err
	}
	fmt.Printf("\t\tFrom:\t%v\n", to)
	fmt.Printf("\t\tMethod:\t%v\n", method2)
	fmt.Printf("\t\tTo:\t%v\n", internal.To)
	fmt.Printf("\t\tValue:\t%v\n", types.FIL(internal.Value))
	if params2 != "" {
		fmt.Printf("\t\tParameters:\t%v\n", params2)
	}
	return nil
}
