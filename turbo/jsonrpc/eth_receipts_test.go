package jsonrpc

import (
	"context"
	"math/big"
	"testing"

	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/gointerfaces/txpool"
	"github.com/ledgerwatch/erigon-lib/kv/kvcache"
	"github.com/ledgerwatch/erigon-lib/kv/memdb"
	"github.com/ledgerwatch/erigon/cmd/rpcdaemon/rpcdaemontest"
	"github.com/ledgerwatch/erigon/common/u256"
	"github.com/ledgerwatch/erigon/core/rawdb"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/rpc/rpccfg"
	"github.com/ledgerwatch/erigon/turbo/rpchelper"
	"github.com/ledgerwatch/erigon/turbo/stages"
	"github.com/ledgerwatch/log/v3"
	"github.com/stretchr/testify/require"
)

func TestGetReceipts(t *testing.T) {
	m, _, _ := rpcdaemontest.CreateTestSentry(t)
	agg := m.HistoryV3Components()
	stateCache := kvcache.New(kvcache.DefaultCoherentConfig)
	ctx, conn := rpcdaemontest.CreateTestGrpcConn(t, stages.Mock(t))
	mining := txpool.NewMiningClient(conn)
	ff := rpchelper.New(ctx, nil, nil, mining, func() {}, m.Log)
	api := NewEthAPI(NewBaseApi(ff, stateCache, m.BlockReader, agg, false, rpccfg.DefaultEvmCallTimeout, m.Engine, m.Dirs), m.DB, nil, nil, nil, 5000000, 100_000, log.New())

	db := memdb.New("")
	defer db.Close()

	tx, err := db.BeginRw(context.Background())
	require.NoError(t, err)
	defer tx.Rollback()

	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(100)}
	block := types.NewBlockWithHeader(header)

	require.NoError(t, rawdb.WriteBlock(tx, block))
	require.NoError(t, rawdb.WriteReceipts(tx, block.NumberU64(), nil))
	tx.Commit()

	rTx, err := db.BeginRo(context.Background())
	require.NoError(t, err)
	defer rTx.Rollback()

	receipt, err := api.getReceipts(m.Ctx, rTx, m.ChainConfig, block, []libcommon.Address{})
	require.NoError(t, err)
	require.Equal(t, 0, len(receipt))

	tx, err = db.BeginRw(context.Background())
	require.NoError(t, err)
	defer tx.Rollback()

	tx1 := types.NewTransaction(1, libcommon.HexToAddress("0x1"), u256.Num1, 1, u256.Num1, nil)
	tx2 := types.NewTransaction(2, libcommon.HexToAddress("0x2"), u256.Num2, 2, u256.Num2, nil)

	header = &types.Header{Number: big.NewInt(2), Difficulty: big.NewInt(100)}
	body := &types.Body{Transactions: types.Transactions{tx1, tx2}}

	receipt1 := &types.Receipt{
		Status:            types.ReceiptStatusFailed,
		CumulativeGasUsed: 1,
		Logs: []*types.Log{
			{Address: libcommon.BytesToAddress([]byte{0x11})},
			{Address: libcommon.BytesToAddress([]byte{0x01, 0x11})},
		},
		TxHash:          tx1.Hash(),
		ContractAddress: libcommon.BytesToAddress([]byte{0x01, 0x11, 0x11}),
		GasUsed:         111111,
		L1Fee:           big.NewInt(7),
		L2BobaFee:       big.NewInt(8),
	}
	receipt2 := &types.Receipt{
		PostState:         libcommon.Hash{2}.Bytes(),
		CumulativeGasUsed: 2,
		Logs: []*types.Log{
			{Address: libcommon.BytesToAddress([]byte{0x22})},
			{Address: libcommon.BytesToAddress([]byte{0x02, 0x22})},
		},
		TxHash:          tx2.Hash(),
		ContractAddress: libcommon.BytesToAddress([]byte{0x02, 0x22, 0x22}),
		GasUsed:         222222,
		L1Fee:           big.NewInt(1),
	}
	receipts := []*types.Receipt{receipt1, receipt2}

	rawdb.WriteCanonicalHash(tx, header.Hash(), header.Number.Uint64())
	rawdb.WriteHeader(tx, header)
	require.NoError(t, rawdb.WriteBody(tx, header.Hash(), 2, body))
	require.NoError(t, rawdb.WriteSenders(tx, header.Hash(), 2, body.SendersFromTxs()))

	br := m.BlockReader
	b, senders, err := br.BlockWithSenders(ctx, tx, header.Hash(), 2)
	require.NoError(t, err)

	require.NoError(t, rawdb.WriteBlock(tx, b))
	require.NoError(t, rawdb.WriteReceipts(tx, b.NumberU64(), receipts))

	tx.Commit()

	rTx, err = db.BeginRo(context.Background())
	require.NoError(t, err)
	defer rTx.Rollback()

	receipts, err = api.getReceipts(m.Ctx, rTx, m.ChainConfig, b, senders)
	require.NoError(t, err)
	require.Equal(t, 2, len(receipts))
	require.Equal(t, receipt1.L1Fee, receipts[0].L1Fee)
	require.Equal(t, receipt1.L2BobaFee, receipts[0].L2BobaFee)
	require.Equal(t, receipt2.L1Fee, receipts[1].L1Fee)
	require.Equal(t, receipt2.L2BobaFee, receipts[1].L2BobaFee)
}
