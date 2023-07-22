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
func CallHC(evm vm.VMInterface, msg core.Message, gp *core.GasPool, refunds bool, gasBailout bool) (result *core.ExecutionResult, err error) {
	if vm.HCResponseCache == nil {
		vm.HCResponseCache = make(map[libcommon.Hash]*vm.HCContext)
	}

	mh := vm.HCKey(msg.From(), msg.To(), msg.Nonce(), msg.Data())
	hc := vm.HCResponseCache[mh]
	if hc == nil {
		hc = new(vm.HCContext)
	}
	evm.SetHC(hc)

	extra := uint64(0)

	if len(hc.Response) > 0 && hc.State < vm.HC_STATE_INSERTED { // FIXME
		// A cached response is available from a prior run

		txn := types.NewOffchainTx(mh, hc.Response)
		log.Debug("MMDBG-HC Inserting HC Response", "hcState", hc.State, "mh", mh, "txn", txn)

		var msg2 types.Message
		msg2, err = txn.AsMessage(types.Signer{}, nil, nil)
		log.Debug("MMDBG-HC call.go AsMessage", "err", err, "msg2", msg2)

		result, err = core.ApplyMessageMM(evm, msg2, gp, refunds, gasBailout, 0)
		log.Debug("MMDBG-HC call.go after HC_ApplyMessage", "err", err, "result", result)
		if err != nil {
			if err != vm.ErrOutOfGas {
				hc.State = vm.HC_STATE_FAILED
			}
			return nil, err
		}
		extra = msg2.RollupDataGas()
		log.Debug("MMDBG-HC call.go passing extra gas", "extra", extra)
	}
	result, err = core.ApplyMessageMM(evm, msg, gp, refunds, gasBailout, extra)
	log.Debug("MMDBG-HC call.go after ApplyMessage", "err", err, "result", result)

	if err == vm.ErrHCReverted {
		if vm.HCResponseCache[mh] == nil {
			log.Debug("MMDBG-HC call.go Offchain triggered", "mh", mh, "hc", hc, "cache", vm.HCResponseCache[mh])

			err = vm.HCRequest(hc, evm.Context().BlockNumber)
			if err != nil {
				log.Warn("MMDBG-HC Request failed", "err", err)
				return nil, vm.ErrHCFailed
			}

			vm.HCResponseCache[mh] = hc
			// the caller will get ErrHCReverted as a signal to retry. The cached response
			// will be used on that call.
		} else {
			if err != vm.ErrOutOfGas {
				hc.State = vm.HC_STATE_FAILED
				log.Warn("MMDBG-HC got ErrHCReverted when applying cached entry")
				return nil, vm.ErrHCFailed
			}
		}
	}
	log.Debug("MMDBG-HC call.go after ApplyMessage3", "err", err, "result", result)

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
	log.Debug("MMDBG-HC CallHC from Call()", "msg", msg)
	result, err := CallHC(evm, msg, gp, true /* refunds */, false /* gasBailout */)
	if err != nil {
		return nil, err
	}

	// If the timer caused an abort, return an appropriate error message
	if evm.Cancelled() {
		log.Warn("MMDBG-HC call.go evm.Cancelled()", "timeout", callTimeout)
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

	log.Debug("MMDBG-HC CallHC from DoCallWithNewGas()", "msg", r.message, "timeout", r.callTimeout)
	result, err := CallHC(r.evm, r.message, gp, true, false)
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
