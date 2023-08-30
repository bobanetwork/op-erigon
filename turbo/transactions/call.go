package transactions

import (
	"context"
	"fmt"
	"time"

	"github.com/holiman/uint256"
	"github.com/ledgerwatch/log/v3"

	"github.com/ledgerwatch/erigon-lib/chain"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/kv"

	"github.com/ledgerwatch/erigon/consensus"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/core/vm/evmtypes"
	"github.com/ledgerwatch/erigon/rpc"
	ethapi2 "github.com/ledgerwatch/erigon/turbo/adapter/ethapi"
	"github.com/ledgerwatch/erigon/turbo/services"
)

// Shared section of DoCall() and DoCallWithNewGas(), with hybrid compute support.
func CallHC(hcs *vm.HCService, evm vm.VMInterface, msg core.Message, gp *core.GasPool, refunds bool, gasBailout bool) (result *core.ExecutionResult, err error) {

	var hc *vm.HCContext

	mh := vm.HCKey(msg.From(), msg.To(), msg.Nonce(), msg.Data())
	if hcs != nil {
		hc = hcs.GetHC(mh)
	}
	if hc == nil {
		hc = new(vm.HCContext)
	}
	evm.SetHC(hc)

	var extra [2]uint64
	if len(hc.Response) > 0 && hc.State < vm.HC_STATE_INSERTED { // FIXME
		// A cached response is available from a prior run

		txn := types.NewOffchainTx(mh, hc.Response, msg.Gas())
		log.Debug("HC CallHC inserting prepared response", "hcState", hc.State, "mh", mh, "txn", txn)

		var msg2 types.Message
		msg2, err = txn.AsMessage(types.Signer{}, nil, nil)
		if err != nil {
			return nil, err
		}

		result, err = core.ApplyMessageHC(evm, msg2, gp, false /* refunds */, gasBailout, &extra)
		log.Debug("HC CallHC after ApplyMessage (offchain)", "err", err, "result", result, "extra", extra)
		if err != nil {
			if err != vm.ErrOutOfGas {
				hc.State = vm.HC_STATE_FAILED
			}
			return nil, err
		}

		// This must be called for the total gas usage in an eth_etimateGas() call to match that of the submitted Tx
		ibs := evm.IntraBlockState()
		ibs.FakeFinalizeTx(evm.ChainRules())
	}

	result, err = core.ApplyMessageHC(evm, msg, gp, refunds, gasBailout, &extra)
	log.Debug("HC CallHC after ApplyMessageHC", "err", err, "gp", gp, "result", result, "msg", msg)

	if err == vm.ErrHCReverted && hcs != nil {
		if hcs.GetHC(mh) == nil {
			log.Debug("HC CallHC triggered Hybrid Compute", "mh", mh, "hc", hc)

			err2 := vm.HCRequest(hcs, hc, evm.Context().BlockNumber)
			if err2 != nil {
				log.Warn("HC Request failed", "err", err)
				return nil, vm.ErrHCFailed
			}

			hcs.PutHC(mh, hc)
			// the caller will get the ErrHCReverted as a signal to retry with the cached response
		} else {
			hc.State = vm.HC_STATE_FAILED
			log.Warn("HC got an unexpected ErrHCReverted")
			return nil, vm.ErrHCFailed
		}
	}

	return result, err
}

func DoCall(
	ctx context.Context,
	engine consensus.EngineReader,
	args ethapi2.CallArgs,
	tx kv.Tx,
	blockNrOrHash rpc.BlockNumberOrHash,
	header *types.Header,
	overrides *ethapi2.StateOverrides,
	gasCap uint64,
	chainConfig *chain.Config,
	stateReader state.StateReader,
	headerReader services.HeaderReader,
	callTimeout time.Duration,
	hcs *vm.HCService,
) (*core.ExecutionResult, error) {
	// todo: Pending state is only known by the miner
	/*
		if blockNrOrHash.BlockNumber != nil && *blockNrOrHash.BlockNumber == rpc.PendingBlockNumber {
			block, state, _ := b.eth.miner.Pending()
			return state, block.Header(), nil
		}
	*/

	state := state.New(stateReader)

	// Override the fields of specified contracts before execution.
	if overrides != nil {
		if err := overrides.Override(state); err != nil {
			return nil, err
		}
	}

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if callTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, callTimeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	// Get a new instance of the EVM.
	var baseFee *uint256.Int
	if header != nil && header.BaseFee != nil {
		var overflow bool
		baseFee, overflow = uint256.FromBig(header.BaseFee)
		if overflow {
			return nil, fmt.Errorf("header.BaseFee uint256 overflow")
		}
	}
	msg, err := args.ToMessage(gasCap, baseFee)
	if err != nil {
		return nil, err
	}

	l1CostFunc := types.NewL1CostFunc(chainConfig, state)
	blockCtx := NewEVMBlockContext(engine, header, blockNrOrHash.RequireCanonical, tx, headerReader, l1CostFunc)
	txCtx := core.NewEVMTxContext(msg)

	evm := vm.NewEVM(blockCtx, txCtx, state, chainConfig, vm.Config{NoBaseFee: true})

	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	gp := new(core.GasPool).AddGas(msg.Gas()).AddDataGas(msg.DataGas())
	result, err := CallHC(hcs, evm, msg, gp, true /* refunds */, false /* gasBailout */)
	if err != nil {
		return nil, err
	}

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		return nil, fmt.Errorf("execution aborted (timeout = %v)", callTimeout)
	}
	return result, nil
}

func NewEVMBlockContext(engine consensus.EngineReader, header *types.Header, requireCanonical bool, tx kv.Tx, headerReader services.HeaderReader, l1CostFunc types.L1CostFunc) evmtypes.BlockContext {
	return core.NewEVMBlockContext(header, MakeHeaderGetter(requireCanonical, tx, headerReader), engine, nil /* author */, l1CostFunc)
}

func MakeHeaderGetter(requireCanonical bool, tx kv.Tx, headerReader services.HeaderReader) func(uint64) libcommon.Hash {
	return func(n uint64) libcommon.Hash {
		h, err := headerReader.HeaderByNumber(context.Background(), tx, n)
		if err != nil {
			log.Error("Can't get block hash by number", "number", n, "only-canonical", requireCanonical)
			return libcommon.Hash{}
		}
		if h == nil {
			log.Warn("[evm] header is nil", "blockNum", n)
			return libcommon.Hash{}
		}
		return h.Hash()
	}
}

type ReusableCaller struct {
	evm             *vm.EVM
	intraBlockState *state.IntraBlockState
	gasCap          uint64
	baseFee         *uint256.Int
	stateReader     state.StateReader
	callTimeout     time.Duration
	message         *types.Message
}

func (r *ReusableCaller) DoCallWithNewGas(
	ctx context.Context,
	newGas uint64,
	hcs *vm.HCService,
) (*core.ExecutionResult, error) {
	var cancel context.CancelFunc
	if r.callTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, r.callTimeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	r.message.ChangeGas(r.gasCap, newGas)

	// reset the EVM so that we can continue to use it with the new context
	txCtx := core.NewEVMTxContext(r.message)
	r.intraBlockState = state.New(r.stateReader)
	r.evm.Reset(txCtx, r.intraBlockState)

	timedOut := false
	go func() {
		<-ctx.Done()
		timedOut = true
	}()

	gp := new(core.GasPool).AddGas(r.message.Gas()).AddDataGas(r.message.DataGas())

	result, err := CallHC(hcs, r.evm, r.message, gp, true, false)
	if err != nil {
		return nil, err
	}

	// If the timer caused an abort, return an appropriate error message
	if timedOut {
		return nil, fmt.Errorf("execution aborted (timeout = %v)", r.callTimeout)
	}

	return result, nil
}

func NewReusableCaller(
	engine consensus.EngineReader,
	stateReader state.StateReader,
	overrides *ethapi2.StateOverrides,
	header *types.Header,
	initialArgs ethapi2.CallArgs,
	gasCap uint64,
	blockNrOrHash rpc.BlockNumberOrHash,
	tx kv.Tx,
	headerReader services.HeaderReader,
	chainConfig *chain.Config,
	callTimeout time.Duration,
) (*ReusableCaller, error) {
	ibs := state.New(stateReader)

	if overrides != nil {
		if err := overrides.Override(ibs); err != nil {
			return nil, err
		}
	}

	var baseFee *uint256.Int
	if header != nil && header.BaseFee != nil {
		var overflow bool
		baseFee, overflow = uint256.FromBig(header.BaseFee)
		if overflow {
			return nil, fmt.Errorf("header.BaseFee uint256 overflow")
		}
	}

	msg, err := initialArgs.ToMessage(gasCap, baseFee)
	if err != nil {
		return nil, err
	}

	l1CostFunc := types.NewL1CostFunc(chainConfig, ibs)
	blockCtx := NewEVMBlockContext(engine, header, blockNrOrHash.RequireCanonical, tx, headerReader, l1CostFunc)
	txCtx := core.NewEVMTxContext(msg)

	evm := vm.NewEVM(blockCtx, txCtx, ibs, chainConfig, vm.Config{NoBaseFee: true})

	return &ReusableCaller{
		evm:             evm,
		intraBlockState: ibs,
		baseFee:         baseFee,
		gasCap:          gasCap,
		callTimeout:     callTimeout,
		stateReader:     stateReader,
		message:         &msg,
	}, nil
}
