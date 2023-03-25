package stagedsync

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/chain"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/log/v3"
	"golang.org/x/net/context"

	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/erigon-lib/kv/memdb"
	"github.com/ledgerwatch/erigon-lib/txpool"
	types2 "github.com/ledgerwatch/erigon-lib/types"

	"github.com/ledgerwatch/erigon/core/types/accounts"
	"github.com/ledgerwatch/erigon/rlp"

	"github.com/ledgerwatch/erigon/core/rawdb"
	"github.com/ledgerwatch/erigon/turbo/services"

	"github.com/ledgerwatch/erigon/consensus"
	"github.com/ledgerwatch/erigon/consensus/misc"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/systemcontracts"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/core/vm"
	"github.com/ledgerwatch/erigon/eth/stagedsync/stages"
	"github.com/ledgerwatch/erigon/params"
	"github.com/ledgerwatch/erigon/turbo/snapshotsync"
)

type MiningExecCfg struct {
	db          kv.RwDB
	miningState MiningState
	notifier    ChainEventNotifier
	chainConfig chain.Config
	engine      consensus.Engine
	blockReader services.FullBlockReader
	vmConfig    *vm.Config
	tmpdir      string
	interrupt   *int32
	payloadId   uint64
	txPool2     *txpool.TxPool
	txPool2DB   kv.RoDB
}

func StageMiningExecCfg(
	db kv.RwDB,
	miningState MiningState,
	notifier ChainEventNotifier,
	chainConfig chain.Config,
	engine consensus.Engine,
	vmConfig *vm.Config,
	tmpdir string,
	interrupt *int32,
	payloadId uint64,
	txPool2 *txpool.TxPool,
	txPool2DB kv.RoDB,
) MiningExecCfg {
	return MiningExecCfg{
		db:          db,
		miningState: miningState,
		notifier:    notifier,
		chainConfig: chainConfig,
		engine:      engine,
		blockReader: snapshotsync.NewBlockReader(),
		vmConfig:    vmConfig,
		tmpdir:      tmpdir,
		interrupt:   interrupt,
		payloadId:   payloadId,
		txPool2:     txPool2,
		txPool2DB:   txPool2DB,
	}
}

// SpawnMiningExecStage
// TODO:
// - resubmitAdjustCh - variable is not implemented
func SpawnMiningExecStage(s *StageState, tx kv.RwTx, cfg MiningExecCfg, quit <-chan struct{}) error {
	cfg.vmConfig.NoReceipts = false
	chainID, _ := uint256.FromBig(cfg.chainConfig.ChainID)
	logPrefix := s.LogPrefix()
	current := cfg.miningState.MiningBlock
	txs := current.PreparedTxs
	noempty := true

	stateReader := state.NewPlainStateReader(tx)
	ibs := state.New(stateReader)
	stateWriter := state.NewPlainStateWriter(tx, tx, current.Header.Number.Uint64())
	if cfg.chainConfig.DAOForkSupport && cfg.chainConfig.DAOForkBlock != nil && cfg.chainConfig.DAOForkBlock.Cmp(current.Header.Number) == 0 {
		misc.ApplyDAOHardFork(ibs)
	}
	systemcontracts.UpgradeBuildInSystemContract(&cfg.chainConfig, current.Header.Number, ibs)

	// Create an empty block based on temporary copied state for
	// sealing in advance without waiting block execution finished.
	if !noempty {
		log.Info("Commit an empty block", "number", current.Header.Number)
		return nil
	}

	getHeader := func(hash libcommon.Hash, number uint64) *types.Header { return rawdb.ReadHeader(tx, hash, number) }

	// Short circuit if there is no available pending transactions.
	// But if we disable empty precommit already, ignore it. Since
	// empty block is necessary to keep the liveness of the network.
	if noempty {
		var cLogs types.Logs

		log.Debug("MMDBG SpawnMiningExecStage", "txs", txs, "Deposits", current.Deposits, "NoTxPool", current.NoTxPool)

		if current.Deposits != nil && len(current.Deposits) != 0 {
		
			var txs []types.Transaction
			for i := range current.Deposits {
				s := rlp.NewStream(bytes.NewReader(current.Deposits[i]), uint64(len(current.Deposits[i])))
                		log.Debug("MMDBG Candidate transaction", "i", i, "tx", current.Deposits[i], "s", s)

				transaction, err := types.DecodeTransaction(s)
                		log.Debug("MMDBG Decoded", "err", err, "tx", transaction)
				if err == io.EOF {
					continue
				}
				if err != nil {
					return err
				}
				txs = append(txs, transaction)
			}
/* FIXME - can now remove
			if !current.NoTxPool && current.Header.Number.Cmp(big.NewInt(5)) == 0 {
				var hcData []byte = []byte{1, 2, 3, 4, 5, 6, 7, 8}
				hcTmp := types.NewOffchainTx(hcData)
				txs = append(txs, hcTmp)
			}
*/
			depTS := types.NewTransactionsFixedOrder(txs)

			logs, _, err := addTransactionsToMiningBlock(logPrefix, current, cfg.chainConfig, cfg.vmConfig, getHeader, cfg.engine, depTS, cfg.miningState.MiningConfig.Etherbase, ibs, quit, cfg.interrupt, cfg.payloadId)
			log.Debug("MMDBG addTransactionsToMiningBlock (deposit)", "err", err, "logs", logs)
			if err != nil {
				return err
			}
			cLogs = append(cLogs, logs...)
		}

		if txs != nil && !txs.Empty() {
			logs, _, err := addTransactionsToMiningBlock(logPrefix, current, cfg.chainConfig, cfg.vmConfig, getHeader, cfg.engine, txs, cfg.miningState.MiningConfig.Etherbase, ibs, quit, cfg.interrupt, cfg.payloadId)
			log.Debug("MMDBG addTransactionsToMiningBlock (txs)", "err", err, "logs", logs)
			if err != nil {
				return err
			}
			NotifyPendingLogs(logPrefix, cfg.notifier, logs)
		} else {

			yielded := mapset.NewSet[[32]byte]()
			simulationTx := memdb.NewMemoryBatch(tx, cfg.tmpdir)
			defer simulationTx.Rollback()
			executionAt, err := s.ExecutionAt(tx)
			if err != nil {
				return err
			}

			for {
				txs, y, err := getNextTransactions(cfg, chainID, current.Header, 50, executionAt, simulationTx, yielded)
				log.Debug("MMDBG addTransactionsToMiningBlock getNextTransactions", "txs", txs, "y", y, "err", err)
				if err != nil {
					return err
				}

				if !txs.Empty() {
					logs, stop, err := addTransactionsToMiningBlock(logPrefix, current, cfg.chainConfig, cfg.vmConfig, getHeader, cfg.engine, txs, cfg.miningState.MiningConfig.Etherbase, ibs, quit, cfg.interrupt, cfg.payloadId)
					log.Debug("MMDBG addTransactionsToMiningBlock (regular)", "err", err, "logs", logs, "stop", stop)
					if err != nil {
						return err
					}
					NotifyPendingLogs(logPrefix, cfg.notifier, logs)
					if stop {
						break
					}
				} else {
					break
				}

				// if we yielded less than the count we wanted, assume the txpool has run dry now and stop to save another loop
				if y < 50 {
					break
				}
			}
		}
	}

	log.Debug("SpawnMiningExecStage", "block txn", current.Txs.Len(), "payload", cfg.payloadId)
	if current.Uncles == nil {
		current.Uncles = []*types.Header{}
	}
	if current.Txs == nil {
		current.Txs = []types.Transaction{}
	}
	if current.Receipts == nil {
		current.Receipts = types.Receipts{}
	}

	var err error
	_, current.Txs, current.Receipts, err = core.FinalizeBlockExecution(cfg.engine, stateReader, current.Header, current.Txs, current.Uncles, stateWriter,
		&cfg.chainConfig, ibs, current.Receipts, current.Withdrawals, EpochReaderImpl{tx: tx}, ChainReaderImpl{config: &cfg.chainConfig, tx: tx, blockReader: cfg.blockReader}, true)
	if err != nil {
		return err
	}
	log.Debug("FinalizeBlockExecution", "current txn", current.Txs.Len(), "current receipt", current.Receipts.Len(), "payload", cfg.payloadId)

	// hack: pretend that we are real execution stage - next stages will rely on this progress
	if err := stages.SaveStageProgress(tx, stages.Execution, current.Header.Number.Uint64()); err != nil {
		return err
	}
	return nil
}

func getNextTransactions(
	cfg MiningExecCfg,
	chainID *uint256.Int,
	header *types.Header,
	amount uint16,
	executionAt uint64,
	simulationTx *memdb.MemoryMutation,
	alreadyYielded mapset.Set[[32]byte],
) (types.TransactionsStream, int, error) {
	txSlots := types2.TxsRlp{}
	var onTime bool
	count := 0
	if err := cfg.txPool2DB.View(context.Background(), func(poolTx kv.Tx) error {
		var err error
		counter := 0
		for !onTime && counter < 1000 {
			remainingGas := header.GasLimit - header.GasUsed
			if onTime, count, err = cfg.txPool2.YieldBest(amount, &txSlots, poolTx, executionAt, remainingGas, alreadyYielded); err != nil {
				return err
			}
			time.Sleep(1 * time.Millisecond)
			counter++
		}
		return nil
	}); err != nil {
		return nil, 0, err
	}

	var txs []types.Transaction //nolint:prealloc
	reader := bytes.NewReader([]byte{})
	stream := new(rlp.Stream)
	for i := range txSlots.Txs {
		reader.Reset(txSlots.Txs[i])
		stream.Reset(reader, uint64(len(txSlots.Txs[i])))

		transaction, err := types.DecodeTransaction(stream)
		if err == io.EOF {
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		if !transaction.GetChainID().IsZero() && transaction.GetChainID().Cmp(chainID) != 0 {
			continue
		}

		var sender libcommon.Address
		copy(sender[:], txSlots.Senders.At(i))

		// Check if tx nonce is too low
		txs = append(txs, transaction)
		txs[len(txs)-1].SetSender(sender)
	}

	blockNum := executionAt + 1
	txs, err := filterBadTransactions(txs, cfg.chainConfig, blockNum, header.BaseFee, simulationTx)
	if err != nil {
		return nil, 0, err
	}

	return types.NewTransactionsFixedOrder(txs), count, nil
}

func filterBadTransactions(transactions []types.Transaction, config chain.Config, blockNumber uint64, baseFee *big.Int, simulationTx *memdb.MemoryMutation) ([]types.Transaction, error) {
	log.Debug("MMDBG entering filterBadTransactions", "num", len(transactions))
	initialCnt := len(transactions)
	var filtered []types.Transaction
	gasBailout := config.Consensus == chain.ParliaConsensus

	missedTxs := 0
	noSenderCnt := 0
	noAccountCnt := 0
	nonceTooLowCnt := 0
	notEOACnt := 0
	feeTooLowCnt := 0
	balanceTooLowCnt := 0
	overflowCnt := 0
	for len(transactions) > 0 && missedTxs != len(transactions) {
		transaction := transactions[0]
		log.Debug("MMDBG filterBadTransactions evaluating", "tx", transaction)

		sender, ok := transaction.GetSender()
		if !ok {
			transactions = transactions[1:]
			noSenderCnt++
			continue
		}
		var account accounts.Account
		ok, err := rawdb.ReadAccount(simulationTx, sender, &account)
		if err != nil {
			return nil, err
		}
		if !ok {
			transactions = transactions[1:]
			noAccountCnt++
			continue
		}
		if int(transaction.Type()) == types.DepositTxType {
			// FIXME - may need to include some of the later checks
			log.Debug("MMDBG bypassing filterBadTransactions for Deposit tx")
			filtered = append(filtered, transaction)
			transactions = transactions[1:]
			continue
		}
		if int(transaction.Type()) == types.OffchainTxType {
			// FIXME - may need to include some of the later checks
			log.Debug("MMDBG bypassing filterBadTransactions for Offchain tx")
			filtered = append(filtered, transaction)
			transactions = transactions[1:]
			continue
		}		// Check transaction nonce
		if account.Nonce > transaction.GetNonce() {
			transactions = transactions[1:]
			nonceTooLowCnt++
			continue
		}
		if account.Nonce < transaction.GetNonce() {
			missedTxs++
			transactions = append(transactions[1:], transaction)
			continue
		}
		missedTxs = 0

		// Make sure the sender is an EOA (EIP-3607)
		if !account.IsEmptyCodeHash() {
			transactions = transactions[1:]
			notEOACnt++
			continue
		}

		if config.IsLondon(blockNumber) {
			baseFee256 := uint256.NewInt(0)
			if overflow := baseFee256.SetFromBig(baseFee); overflow {
				return nil, fmt.Errorf("bad baseFee %s", baseFee)
			}
			// Make sure the transaction gasFeeCap is greater than the block's baseFee.
			if !transaction.GetFeeCap().IsZero() || !transaction.GetTip().IsZero() {
				if err := core.CheckEip1559TxGasFeeCap(sender, transaction.GetFeeCap(), transaction.GetTip(), baseFee256, false /* isFree */); err != nil {
					transactions = transactions[1:]
					feeTooLowCnt++
					continue
				}
			}
		}
		txnGas := transaction.GetGas()
		txnPrice := transaction.GetPrice()
		value := transaction.GetValue()
		accountBalance := account.Balance

		want := uint256.NewInt(0)
		want.SetUint64(txnGas)
		want, overflow := want.MulOverflow(want, txnPrice)
		if overflow {
			transactions = transactions[1:]
			overflowCnt++
			continue
		}

		if transaction.GetFeeCap() != nil {
			want.SetUint64(txnGas)
			want, overflow = want.MulOverflow(want, transaction.GetFeeCap())
			if overflow {
				transactions = transactions[1:]
				overflowCnt++
				continue
			}
			want, overflow = want.AddOverflow(want, value)
			if overflow {
				transactions = transactions[1:]
				overflowCnt++
				continue
			}
		}

		if accountBalance.Cmp(want) < 0 {
			if !gasBailout {
				transactions = transactions[1:]
				balanceTooLowCnt++
				continue
			}
		}
		// Updates account in the simulation
		account.Nonce++
		account.Balance.Sub(&account.Balance, want)
		accountBuffer := make([]byte, account.EncodingLengthForStorage())
		account.EncodeForStorage(accountBuffer)
		if err := simulationTx.Put(kv.PlainState, sender[:], accountBuffer); err != nil {
			return nil, err
		}
		// Mark transaction as valid
		filtered = append(filtered, transaction)
		transactions = transactions[1:]
	}
	log.Debug("MMDBG leaving filterBadTransactions", "filtered", filtered)
	log.Debug("Filtration", "initial", initialCnt, "no sender", noSenderCnt, "no account", noAccountCnt, "nonce too low", nonceTooLowCnt, "nonceTooHigh", missedTxs, "sender not EOA", notEOACnt, "fee too low", feeTooLowCnt, "overflow", overflowCnt, "balance too low", balanceTooLowCnt, "filtered", len(filtered))
	return filtered, nil
}

func addTransactionsToMiningBlock(logPrefix string, current *MiningBlock, chainConfig chain.Config, vmConfig *vm.Config, getHeader func(hash libcommon.Hash, number uint64) *types.Header, engine consensus.Engine, txs types.TransactionsStream, coinbase libcommon.Address, ibs *state.IntraBlockState, quit <-chan struct{}, interrupt *int32, payloadId uint64) (types.Logs, bool, error) {
	header := current.Header
	tcount := 0
	gasPool := new(core.GasPool).AddGas(header.GasLimit - header.GasUsed)
	signer := types.MakeSigner(&chainConfig, header.Number.Uint64())

	var coalescedLogs types.Logs
	noop := state.NewNoopWriter()

	var miningCommitTx = func(txn types.Transaction, coinbase libcommon.Address, vmConfig *vm.Config, chainConfig chain.Config, ibs *state.IntraBlockState, current *MiningBlock, hc *vm.HCContext) ([]*types.Log, error) {
		ibs.Prepare(txn.Hash(), libcommon.Hash{}, tcount)
		gasSnap := gasPool.Gas()
		snap := ibs.Snapshot()
		log.Debug("miningCommitTx calling addTransactionsToMiningBlock", "tcount", tcount, "txn hash", txn.Hash())
		
		receipt, _, err := core.ApplyTransactionMM(&chainConfig, core.GetHashFn(header, getHeader), engine, &coinbase, gasPool, ibs, noop, header, txn, &header.GasUsed, *vmConfig, hc)
		log.Debug("MMDBG-HC miningCommitTx", "err", err, "receipt", receipt, "hc", hc)
		
		if err != nil {
			ibs.RevertToSnapshot(snap)
			gasPool = new(core.GasPool).AddGas(gasSnap) // restore gasPool as well as ibs
			return nil, err
		}

		current.Txs = append(current.Txs, txn)
		current.Receipts = append(current.Receipts, receipt)
		log.Debug("MMDBG-HC mCT final", "txn", txn, "current", current)
		return receipt.Logs, nil
	}

	var stopped *time.Ticker
	defer func() {
		if stopped != nil {
			stopped.Stop()
		}
	}()

	done := false
	var hcOffchain bool
	var hc *vm.HCContext

//	log.Debug("MMDBG-HC before addTransactionsToMiningBlock loop")
	if vm.HCResponseCache == nil {
		vm.HCResponseCache = make(map[libcommon.Hash] *vm.HCContext)
	}

LOOP:
	for {
//		log.Debug("MMDBG-HC top of addTransactionsToMiningBlock loop", "hcFlag", hcFlag, "tcount", tcount, "cL", coalescedLogs)
		// see if we need to stop now
		if stopped != nil {
			select {
			case <-stopped.C:
				done = true
				break LOOP
			default:
			}
		}

		if err := libcommon.Stopped(quit); err != nil {
			return nil, true, err
		}

		if interrupt != nil && atomic.LoadInt32(interrupt) != 0 && stopped == nil {
			log.Debug("Transaction adding was requested to stop", "payload", payloadId)
			// ensure we run for at least 500ms after the request to stop comes in from GetPayload
			stopped = time.NewTicker(500 * time.Millisecond)
		}
		// If we don't have enough gas for any further transactions then we're done
		if gasPool.Gas() < params.TxGas {
			log.Debug(fmt.Sprintf("[%s] Not enough gas for further transactions", logPrefix), "have", gasPool, "want", params.TxGas)
			done = true
			break
		}
		
		var txn types.Transaction
		var from libcommon.Address
		var err error
		if false /* hcFlag == 1 */ {
			var hcData []byte = []byte{151, 80, 9, 113}
			
			// Pasted from legacy l2geth
			// Generate cryptographically strong pseudo-random int between 0 - 2^256 - 1
			one := big.NewInt(1)
			two := big.NewInt(2)
			max := new(big.Int)
			// Max random value 2^256 - 1
			max = max.Exp(two, big.NewInt(int64(256)), nil).Sub(max, one)
			randomBigInt, err := rand.Int(rand.Reader, max)

			if err != nil {
				log.Error("MMDBG-HC TURING bobaTuringRandom:Random Number Generation Failed", "err", err)
				//hcFlag = 3
				continue
			}

			log.Debug("MMDBG-HC TURING bobaTuringRandom:Random number",
				"randomBigInt", randomBigInt)
			rNum, _ := uint256.FromBig(randomBigInt)
			
			rNum32 := rNum.Bytes32()
			hcData = append(hcData, rNum32[:]...) 
			
			txn = types.NewOffchainTx(hcData)
			log.Debug("MMDBG-HC Inserting OffchainTx", "txn", txn)
			//hcFlag = 2
		} else {
			hcOffchain = false

			// Retrieve the next transaction and abort if all done
			txn = txs.Peek()
			if txn == nil {
//				log.Debug("MMDBG-HC No more transactions", "cL", coalescedLogs)
				break
			}

			// We use the eip155 signer regardless of the env hf.
			from, err = txn.Sender(*signer)
			if err != nil {
				log.Warn(fmt.Sprintf("[%s] Could not recover transaction sender", logPrefix), "hash", txn.Hash(), "err", err)
				txs.Pop()
				continue
			}

			// Check whether the txn is replay protected. If we're not in the EIP155 (Spurious Dragon) hf
			// phase, start ignoring the sender until we do.
			if txn.Protected() && !chainConfig.IsSpuriousDragon(header.Number.Uint64()) {
				log.Debug(fmt.Sprintf("[%s] Ignoring replay protected transaction", logPrefix), "hash", txn.Hash(), "eip155", chainConfig.SpuriousDragonBlock)

				txs.Pop()
				continue
			}

			// Intercept point for Hybrid Compute. If Txn was previously simulated to populate a cache entry, then insert
			// an OffchainTx into the queue ahead of it to populate the on-chain helper
			
			txnFrom,_ := txn.GetSender()
			mh := vm.HCKey(txnFrom, txn.GetNonce(), txn.GetData())
			hc = vm.HCResponseCache[mh]
			log.Debug("MMDBG-HC Transaction Peek",  "txn", txn, "mh", mh, "hc", hc)
			if hc != nil && !hc.Failed && hc.HcFlag == 2 && len(hc.Response) > 0 {
				log.Debug("MMDBG-HC Found a prepared", "hc.Response", hc.Response)
				txn = types.NewOffchainTx(hc.Response)
				log.Debug("MMDBG-HC Inserting OffchainTx", "txn", txn)
				hc.HcFlag = 3 // Ensure that OffchainTx is only inserted once
				hcOffchain = true
			}
			
			if hc == nil {
				hc = new(vm.HCContext)
			}
		}

		// Start executing the transaction


		logs, err := miningCommitTx(txn, coinbase, vmConfig, chainConfig, ibs, current, hc)
		
		if err == vm.ErrHCReverted {
			log.Warn("MMDBG-HC stage_mining_exec got ErrHCReverted", "hc", hc, "txn", txn)
			hc.HcFlag = 4
			hc.Failed = true

			txnFrom,_ := txn.GetSender()			
			mh := vm.HCKey(txnFrom, txn.GetNonce(), txn.GetData())
			vm.HCResponseCache[mh] = hc

			continue
		}
			
/*		
			if hcFlag == 0 {
				// FIXME - This would now mean no EstimateGas(). Need to queue a background process
				// to do the offchain lookup then defer the Txn until it's completed. For now we
				// insist on a cached result from estimateGas. 
				log.Debug("MMDBG-HC HybridCompute triggered", "txn", txn, "request", hc.Request)
				hcFlag = 1
				continue
			} else if hcFlag == 2 {
				log.Warn("MMDBG-HC OffchainTx failed", "hcFlag", hcFlag, "txn", txn)
				hcFlag = 3 // Will not try to intercept the original txn next time
				continue
			}
		}
*/
		if errors.Is(err, core.ErrGasLimitReached) {
			// Pop the env out-of-gas transaction without shifting in the next from the account
			log.Debug(fmt.Sprintf("[%s] Gas limit exceeded for env block", logPrefix), "hash", txn.Hash(), "sender", from)
			txs.Pop()
		} else if errors.Is(err, core.ErrNonceTooLow) {
			// New head notification data race between the transaction pool and miner, shift
			log.Debug(fmt.Sprintf("[%s] Skipping transaction with low nonce", logPrefix), "hash", txn.Hash(), "sender", from, "nonce", txn.GetNonce())
			txs.Shift()
		} else if errors.Is(err, core.ErrNonceTooHigh) {
			// Reorg notification data race between the transaction pool and miner, skip account =
			log.Debug(fmt.Sprintf("[%s] Skipping transaction with high nonce", logPrefix), "hash", txn.Hash(), "sender", from, "nonce", txn.GetNonce())
			txs.Pop()
		} else if err == nil {
			// Everything ok, collect the logs and shift in the next transaction from the same account
			log.Debug(fmt.Sprintf("[%s] addTransactionsToMiningBlock Successful", logPrefix), "sender", from, "nonce", txn.GetNonce(), "payload", payloadId)
			coalescedLogs = append(coalescedLogs, logs...)
			tcount++
			log.Debug("MMDBG-HC transaction OK", "tcount", tcount, "hcOffchain", hcOffchain)
			if !hcOffchain {
				txnFrom,_ := txn.GetSender()			
				mh := vm.HCKey(txnFrom, txn.GetNonce(), txn.GetData())
				log.Debug("MMDBG-HC Remove from cache", "mh", mh)
				delete(vm.HCResponseCache, mh)
				txs.Shift()
			}
			// FIXME - remove HC cache entry
		} else {
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Debug(fmt.Sprintf("[%s] Skipping transaction", logPrefix), "hash", txn.Hash(), "sender", from, "err", err)
			txs.Shift()
		}
	}
//	log.Debug("MMDBG-HC after addTransactionsToMiningBlock loop", "tcount", tcount, "current", current)

	/*
		// Notify resubmit loop to decrease resubmitting interval if env interval is larger
		// than the user-specified one.
		if interrupt != nil {
			w.resubmitAdjustCh <- &intervalAdjust{inc: false}
		}
	*/
	return coalescedLogs, done, nil

}

func NotifyPendingLogs(logPrefix string, notifier ChainEventNotifier, logs types.Logs) {
	if len(logs) == 0 {
		return
	}

	if notifier == nil {
		log.Debug(fmt.Sprintf("[%s] rpc notifier is not set, rpc daemon won't be updated about pending logs", logPrefix))
		return
	}
	notifier.OnNewPendingLogs(logs)
}
