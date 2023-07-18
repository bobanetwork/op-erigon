package stagedsync

import (
	"context"
	"fmt"

	"github.com/ledgerwatch/erigon-lib/chain"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/log/v3"

	"github.com/ledgerwatch/erigon/common/hexutil"
	"github.com/ledgerwatch/erigon/consensus"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/rpc"
)

type MiningFinishCfg struct {
	db            kv.RwDB
	chainConfig   chain.Config
	engine        consensus.Engine
	sealCancel    chan struct{}
	miningState   MiningState
	historicalRPC *rpc.Client
}

func StageMiningFinishCfg(
	db kv.RwDB,
	chainConfig chain.Config,
	engine consensus.Engine,
	miningState MiningState,
	sealCancel chan struct{},
	historicalRPC *rpc.Client,
) MiningFinishCfg {
	return MiningFinishCfg{
		db:            db,
		chainConfig:   chainConfig,
		engine:        engine,
		miningState:   miningState,
		sealCancel:    sealCancel,
		historicalRPC: historicalRPC,
	}
}

func SpawnMiningFinishStage(s *StageState, tx kv.RwTx, cfg MiningFinishCfg, quit <-chan struct{}) error {
	logPrefix := s.LogPrefix()
	current := cfg.miningState.MiningBlock

	// Short circuit when receiving duplicate result caused by resubmitting.
	//if w.chain.HasBlock(block.Hash(), block.NumberU64()) {
	//	continue
	//}

	var r types.LegacyHeaderMarshaling
	err := cfg.historicalRPC.CallContext(context.Background(), &r, "eth_getBlockByNumber", hexutil.EncodeBig(current.Header.Number), false)
	if err != nil {
		return err
	}
	current.Header.GasUsed = r.GasUsed.ToInt().Uint64()
	current.Header.GasLimit = r.GasLimit.ToInt().Uint64()
	current.Header.Difficulty = r.Difficulty.ToInt()
	current.Header.Root = r.Root
	current.Header.Extra = r.Extra
	current.Header.BaseFee = libcommon.Big0

	block := types.NewBlock(current.Header, current.Txs, current.Uncles, current.Receipts, current.Withdrawals)
	blockWithReceipts := &types.BlockWithReceipts{Block: block, Receipts: current.Receipts}
	*current = MiningBlock{} // hack to clean global data

	//sealHash := engine.SealHash(block.Header())
	// Reject duplicate sealing work due to resubmitting.
	//if sealHash == prev {
	//	s.Done()
	//	return nil
	//}
	//prev = sealHash

	if cfg.miningState.MiningResultPOSCh != nil {
		cfg.miningState.MiningResultPOSCh <- blockWithReceipts
		return nil
	}
	// Tests may set pre-calculated nonce
	if block.NonceU64() != 0 {
		cfg.miningState.MiningResultCh <- block
		return nil
	}

	cfg.miningState.PendingResultCh <- block

	if block.Transactions().Len() > 0 {
		log.Info(fmt.Sprintf("[%s] block ready for seal", logPrefix),
			"block_num", block.NumberU64(),
			"transactions", block.Transactions().Len(),
			"gas_used", block.GasUsed(),
			"gas_limit", block.GasLimit(),
			"difficulty", block.Difficulty(),
		)
	}
	// interrupt aborts the in-flight sealing task.
	select {
	case cfg.sealCancel <- struct{}{}:
	default:
		log.Trace("None in-flight sealing task.")
	}
	chain := ChainReader{Cfg: cfg.chainConfig, Db: tx}
	if err := cfg.engine.Seal(chain, block, cfg.miningState.MiningResultCh, cfg.sealCancel); err != nil {
		log.Warn("Block sealing failed", "err", err)
	}

	return nil
}
