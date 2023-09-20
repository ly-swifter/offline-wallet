package wallet

import (
	"context"
	"fmt"
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/big"
	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/build"
	"github.com/filecoin-project/lotus/chain/store"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/lotus/chain/vm"
	"github.com/ipfs/go-cid"
	"golang.org/x/xerrors"
	stdbig "math/big"
	"time"
	build2 "offline-wallet/build"
)

var baseFeeLowerBoundFactor = types.NewInt(10)
var baseFeeUpperBoundFactor = types.NewInt(10)
var minimumBaseFee = types.NewInt(uint64(build.MinimumBaseFee))

const MaxMessageSize = 64 << 10 // 64KiB

func (sw *ShedWallet) StateWaitMsg(ctx context.Context, cid cid.Cid, confidence uint64, limit abi.ChainEpoch, allowReplaced bool) (*api.MsgLookup, error) {
	mtwkName, err := sw.Gateway.StateNetworkName(ctx)
	if err != nil {
		return nil, err
	}

	fmt.Printf("BlockExplorer:\t%v\n", fmt.Sprintf(build2.BlockExplorer[mtwkName], cid))
	var found = make(chan struct{})
	go func() {
		searchTimer := time.NewTimer(0)
		for {
			select {
			case <-ctx.Done():
				close(found)
			case <-searchTimer.C:
				r, _ := sw.Gateway.StateSearchMsg(ctx, types.EmptyTSK, cid, limit, allowReplaced)
				if r != nil {
					if found != nil {
						found <- struct{}{}
					}
					return
				}
				searchTimer.Reset(10 * time.Second)
			}
		}
	}()

	confidenceSleep := time.Duration(confidence) * time.Duration(build.BlockDelaySecs) * time.Second
	if confidence != 0 {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(confidenceSleep):
					if found != nil {
						found <- struct{}{}
					}
				}
			}
		}()
	}
	for {
		select {
		case <-ctx.Done():
			return nil, xerrors.Errorf("ctx done")
		case <-found:
			r, _ := sw.Gateway.StateSearchMsg(ctx, types.EmptyTSK, cid, limit, allowReplaced)
			if r != nil {
				msg, err := sw.ChainGetMessage(ctx, cid)
				if err != nil {
					return nil, err
				}
				fmt.Println()
				fmt.Println("Message Details Overview:")
				PrintMessageInfo(ctx, msg, sw.Gateway)
				fmt.Println()
				fmt.Println("Message Details Others:")
				PrintMessageReceiptInfo(ctx, sw.Gateway, msg, r)
				return r, nil
			}
		}
	}
}

func (sw *ShedWallet) CheckMessages(ctx context.Context, protos []*api.MessagePrototype) ([][]api.MessageCheckStatus, error) {
	flex := make([]bool, len(protos))
	msgs := make([]*types.Message, len(protos))
	for i, p := range protos {
		flex[i] = !p.ValidNonce
		msgs[i] = &p.Message
	}
	return sw.checkMessages(ctx, msgs, false, flex)
}

// flexibleNonces should be either nil or of len(msgs), it signifies that message at given index
// has non-determied nonce at this point
func (sw *ShedWallet) checkMessages(ctx context.Context, msgs []*types.Message, interned bool, flexibleNonces []bool) (result [][]api.MessageCheckStatus, err error) {

	curTs, err := sw.ChainHead(ctx)
	if err != nil {
		return nil, err
	}
	epoch := curTs.Height() + 1

	var baseFee big.Int
	if len(curTs.Blocks()) > 0 {
		baseFee = curTs.Blocks()[0].ParentBaseFee
	} else {
		baseFee, err = sw.ComputeBaseFee(context.Background(), curTs)
		if err != nil {
			return nil, xerrors.Errorf("error computing basefee: %w", err)
		}
	}

	baseFeeLowerBound := getBaseFeeLowerBound(baseFee, baseFeeLowerBoundFactor)
	baseFeeUpperBound := types.BigMul(baseFee, baseFeeUpperBoundFactor)

	type actorState struct {
		nextNonce     uint64
		requiredFunds *stdbig.Int
	}

	state := make(map[address.Address]*actorState)
	balances := make(map[address.Address]big.Int)

	result = make([][]api.MessageCheckStatus, len(msgs))

	for i, m := range msgs {
		// pre-check: actor nonce
		check := api.MessageCheckStatus{
			Cid: m.Cid(),
			CheckStatus: api.CheckStatus{
				Code: api.CheckStatusMessageGetStateNonce,
			},
		}

		st, ok := state[m.From]
		if !ok {
			stateNonce, err := sw.MpoolGetNonce(ctx, m.From)
			if err != nil {
				check.OK = false
				check.Err = fmt.Sprintf("error retrieving state nonce: %s", err.Error())
			} else {
				check.OK = true
				check.Hint = map[string]interface{}{
					"nonce": stateNonce,
				}
			}

			st = &actorState{nextNonce: stateNonce, requiredFunds: new(stdbig.Int)}
			state[m.From] = st
		} else {
			check.OK = true
		}

		result[i] = append(result[i], check)
		if !check.OK {
			continue
		}

		// pre-check: actor balance
		check = api.MessageCheckStatus{
			Cid: m.Cid(),
			CheckStatus: api.CheckStatus{
				Code: api.CheckStatusMessageGetStateBalance,
			},
		}

		balance, ok := balances[m.From]
		if !ok {
			act, err := sw.GetActor(ctx, m.From, curTs.Key())
			if err != nil {
				check.OK = false
				check.Err = fmt.Sprintf("error retrieving state balance: %s", err)
			} else {
				balance = act.Balance
				check.OK = true
				check.Hint = map[string]interface{}{
					"balance": balance,
				}
			}
			balances[m.From] = balance
		} else {
			check.OK = true
			check.Hint = map[string]interface{}{
				"balance": balance,
			}
		}

		result[i] = append(result[i], check)
		if !check.OK {
			continue
		}

		// 1. Serialization
		check = api.MessageCheckStatus{
			Cid: m.Cid(),
			CheckStatus: api.CheckStatus{
				Code: api.CheckStatusMessageSerialize,
			},
		}

		bytes, err := m.Serialize()
		if err != nil {
			check.OK = false
			check.Err = err.Error()
		} else {
			check.OK = true
		}

		result[i] = append(result[i], check)

		// 2. Message size
		check = api.MessageCheckStatus{
			Cid: m.Cid(),
			CheckStatus: api.CheckStatus{
				Code: api.CheckStatusMessageSize,
			},
		}

		if len(bytes) > MaxMessageSize-128 { // 128 bytes to account for signature size
			check.OK = false
			check.Err = "message too big"
		} else {
			check.OK = true
		}

		result[i] = append(result[i], check)

		// 3. Syntactic validation
		check = api.MessageCheckStatus{
			Cid: m.Cid(),
			CheckStatus: api.CheckStatus{
				Code: api.CheckStatusMessageValidity,
			},
		}
		nv, err := sw.StateNetworkVersion(ctx, types.EmptyTSK)
		if err != nil {
			check.OK = false
			check.Err = fmt.Sprintf("error retrieving network version: %s", err.Error())
		} else {
			check.OK = true
		}
		if err := m.ValidForBlockInclusion(0, nv); err != nil {
			check.OK = false
			check.Err = fmt.Sprintf("syntactically invalid message: %s", err.Error())
		} else {
			check.OK = true
		}

		result[i] = append(result[i], check)
		if !check.OK {
			// skip remaining checks if it is a syntatically invalid message
			continue
		}

		// gas checks

		// 4. Min Gas
		minGas := vm.PricelistByEpoch(epoch).OnChainMessage(m.ChainLength())

		check = api.MessageCheckStatus{
			Cid: m.Cid(),
			CheckStatus: api.CheckStatus{
				Code: api.CheckStatusMessageMinGas,
				Hint: map[string]interface{}{
					"minGas": minGas,
				},
			},
		}

		if m.GasLimit < minGas.Total() {
			check.OK = false
			check.Err = "GasLimit less than epoch minimum gas"
		} else {
			check.OK = true
		}

		result[i] = append(result[i], check)

		// 5. Min Base Fee
		check = api.MessageCheckStatus{
			Cid: m.Cid(),
			CheckStatus: api.CheckStatus{
				Code: api.CheckStatusMessageMinBaseFee,
			},
		}

		if m.GasFeeCap.LessThan(minimumBaseFee) {
			check.OK = false
			check.Err = "GasFeeCap less than minimum base fee"
		} else {
			check.OK = true
		}

		result[i] = append(result[i], check)
		if !check.OK {
			goto checkState
		}

		// 6. Base Fee
		check = api.MessageCheckStatus{
			Cid: m.Cid(),
			CheckStatus: api.CheckStatus{
				Code: api.CheckStatusMessageBaseFee,
				Hint: map[string]interface{}{
					"baseFee": baseFee,
				},
			},
		}

		if m.GasFeeCap.LessThan(baseFee) {
			check.OK = false
			check.Err = "GasFeeCap less than current base fee"
		} else {
			check.OK = true
		}

		result[i] = append(result[i], check)

		// 7. Base Fee lower bound
		check = api.MessageCheckStatus{
			Cid: m.Cid(),
			CheckStatus: api.CheckStatus{
				Code: api.CheckStatusMessageBaseFeeLowerBound,
				Hint: map[string]interface{}{
					"baseFeeLowerBound": baseFeeLowerBound,
					"baseFee":           baseFee,
				},
			},
		}

		if m.GasFeeCap.LessThan(baseFeeLowerBound) {
			check.OK = false
			check.Err = "GasFeeCap less than base fee lower bound for inclusion in next 20 epochs"
		} else {
			check.OK = true
		}

		result[i] = append(result[i], check)

		// 8. Base Fee upper bound
		check = api.MessageCheckStatus{
			Cid: m.Cid(),
			CheckStatus: api.CheckStatus{
				Code: api.CheckStatusMessageBaseFeeUpperBound,
				Hint: map[string]interface{}{
					"baseFeeUpperBound": baseFeeUpperBound,
					"baseFee":           baseFee,
				},
			},
		}

		if m.GasFeeCap.LessThan(baseFeeUpperBound) {
			check.OK = true // on purpose, the checks is more of a warning
			check.Err = "GasFeeCap less than base fee upper bound for inclusion in next 20 epochs"
		} else {
			check.OK = true
		}

		result[i] = append(result[i], check)

		// stateful checks
	checkState:
		// 9. Message Nonce
		check = api.MessageCheckStatus{
			Cid: m.Cid(),
			CheckStatus: api.CheckStatus{
				Code: api.CheckStatusMessageNonce,
				Hint: map[string]interface{}{
					"nextNonce": st.nextNonce,
				},
			},
		}

		if (flexibleNonces == nil || !flexibleNonces[i]) && st.nextNonce != m.Nonce {
			check.OK = false
			check.Err = fmt.Sprintf("message nonce doesn't match next nonce (%d)", st.nextNonce)
		} else {
			check.OK = true
			st.nextNonce++
		}

		result[i] = append(result[i], check)

		// check required funds -vs- balance
		st.requiredFunds = new(stdbig.Int).Add(st.requiredFunds, m.RequiredFunds().Int)
		st.requiredFunds.Add(st.requiredFunds, m.Value.Int)

		// 10. Balance
		check = api.MessageCheckStatus{
			Cid: m.Cid(),
			CheckStatus: api.CheckStatus{
				Code: api.CheckStatusMessageBalance,
				Hint: map[string]interface{}{
					"requiredFunds": big.Int{Int: stdbig.NewInt(0).Set(st.requiredFunds)},
				},
			},
		}

		if balance.Int.Cmp(st.requiredFunds) < 0 {
			check.OK = false
			check.Err = "insufficient balance"
		} else {
			check.OK = true
		}

		result[i] = append(result[i], check)
	}

	return result, nil
}

func (sw *ShedWallet) ComputeBaseFee(ctx context.Context, ts *types.TipSet) (abi.TokenAmount, error) {
	if ts.Height() > build.UpgradeBreezeHeight && ts.Height() < build.UpgradeBreezeHeight+build.BreezeGasTampingDuration {
		return abi.NewTokenAmount(100), nil
	}

	zero := abi.NewTokenAmount(0)

	// totalLimit is sum of GasLimits of unique messages in a tipset
	totalLimit := int64(0)

	seen := make(map[cid.Cid]struct{})

	for _, b := range ts.Blocks() {
		msgs, err := sw.ChainGetBlockMessages(ctx, b.Cid())
		if err != nil {
			return zero, xerrors.Errorf("error getting messages for: %s: %w", b.Cid(), err)
		}
		for _, m := range msgs.BlsMessages {
			c := m.Cid()
			if _, ok := seen[c]; !ok {
				totalLimit += m.GasLimit
				seen[c] = struct{}{}
			}
		}
		for _, m := range msgs.SecpkMessages {
			c := m.Cid()
			if _, ok := seen[c]; !ok {
				totalLimit += m.Message.GasLimit
				seen[c] = struct{}{}
			}
		}
	}
	parentBaseFee := ts.Blocks()[0].ParentBaseFee

	return store.ComputeNextBaseFee(parentBaseFee, totalLimit, len(ts.Blocks()), ts.Height()), nil
}

func getBaseFeeLowerBound(baseFee, factor types.BigInt) types.BigInt {
	baseFeeLowerBound := types.BigDiv(baseFee, factor)
	if baseFeeLowerBound.LessThan(minimumBaseFee) {
		baseFeeLowerBound = minimumBaseFee
	}

	return baseFeeLowerBound
}
