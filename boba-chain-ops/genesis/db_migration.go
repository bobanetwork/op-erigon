package genesis

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/common"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/common/datadir"
	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/erigon-lib/kv/rawdbv3"
	"github.com/ledgerwatch/erigon/consensus/ethash"
	"github.com/ledgerwatch/erigon/consensus/serenity"
	"github.com/ledgerwatch/erigon/core/rawdb"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/erigon/node"
	"github.com/ledgerwatch/erigon/node/nodecfg"
	"github.com/ledgerwatch/erigon/params"
)

func MigrateDB(dbPath string, allocPath string, genesisConfigPath string, mdbxDBSize string) error {
	// for testing purpose
	// remove dbPath
	defer os.RemoveAll(dbPath)

	// load alloc file
	file, err := os.Open(allocPath)
	if err != nil {
		log.Error("failed to open alloc file", "err", err)
		return err
	}
	defer file.Close()

	bytes, _ := ioutil.ReadAll(file)
	genesisAccount, err := MigrateAlloc(bytes)
	if err != nil {
		log.Error("failed to migrate alloc", "err", err)
		return err
	}

	// load genesis config
	genesisCfgFile, err := os.Open(genesisConfigPath)
	if err != nil {
		log.Error("failed to open genesis config file", "err", err)
		return err
	}
	defer genesisCfgFile.Close()

	genesis := new(types.Genesis)
	if err := json.NewDecoder(genesisCfgFile).Decode(genesis); err != nil {
		log.Error("failed to decode genesis config file", "err", err)
		return err
	}
	genesis.Alloc = genesisAccount

	// Open and initialise both full and light databases
	nodeConfig := nodecfg.DefaultConfig
	if err := nodeConfig.MdbxDBSizeLimit.UnmarshalText([]byte(mdbxDBSize)); err != nil {
		log.Error("failed to parse mdbx db size limit", "err", err)
		return err
	}
	szLimit := nodeConfig.MdbxDBSizeLimit.Bytes()
	if szLimit%256 != 0 || szLimit < 256 {
		log.Error("mdbx db size limit must be a multiple of 256 bytes and at least 256 bytes", "limit", szLimit)
		return err
	}
	nodeConfig.Dirs = datadir.New(dbPath)

	stack, err := node.New(&nodeConfig)
	defer stack.Close()

	chaindb, err := node.OpenDatabase(stack.Config(), kv.ChainDB)
	if err != nil {
		log.Error("failed to open chaindb", "err", err)
		return err
	}
	defer chaindb.Close()

	// write genesis to chaindb
	tx, err := chaindb.BeginRw(context.Background())
	if err != nil {
		log.Error("failed to begin write genesis block", "err", err)
		return err
	}
	defer tx.Rollback()

	hash, err := rawdb.ReadCanonicalHash(tx, 0)
	if err != nil {
		log.Error("failed to read canonical hash of block #0", "err", err)
		return err
	}

	if (hash != common.Hash{}) {
		log.Error("genesis block already exists")
		return errors.New("genesis block already exists")
	}

	header, err := CreateHeader(genesis)
	if err != nil {
		log.Error("failed to create header from genesis config", "err", err)
		return err
	}

	statedb, err := AllocToGenesis(genesis, header)
	if err != nil {
		log.Error("failed to create genesis state", "err", err)
		return err
	}

	block := types.NewBlock(header, nil, nil, nil, []*types.Withdrawal{})

	var stateWriter state.StateWriter
	for addr, account := range genesis.Alloc {
		if len(account.Code) > 0 || len(account.Storage) > 0 {
			// Special case for weird tests - inaccessible storage
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], state.FirstContractIncarnation)
			if err := tx.Put(kv.IncarnationMap, addr[:], b[:]); err != nil {
				return err
			}
		}
	}

	stateWriter = state.NewPlainStateWriter(tx, tx, 0)

	if block.Number().Sign() != 0 {
		return fmt.Errorf("genesis block number is not 0")
	}

	if err := statedb.CommitBlock(&chain.Rules{}, stateWriter); err != nil {
		return fmt.Errorf("cannot commit genesis block: %w", err)
	}
	if csw, ok := stateWriter.(state.WriterWithChangeSets); ok {
		if err := csw.WriteChangeSets(); err != nil {
			return fmt.Errorf("cannot write changesets: %w", err)
		}
		if err := csw.WriteHistory(); err != nil {
			return fmt.Errorf("cannot write history: %w", err)
		}
	}

	if err := write(tx, genesis, "", block, statedb); err != nil {
		log.Error("failed to write genesis block", "err", err)
		return err
	}

	err = tx.Commit()
	if err != nil {
		log.Error("failed to commit genesis block", "err", err)
		return err
	}
	log.Info("Successfully wrote genesis state", "hash", block.Hash())

	return nil
}

// Write writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func write(tx kv.RwTx, g *types.Genesis, tmpDir string, block *types.Block, statedb *state.IntraBlockState) error {
	config := g.Config
	if config == nil {
		config = params.AllProtocolChanges
	}
	if err := config.CheckConfigForkOrder(); err != nil {
		return err
	}
	if err := rawdb.WriteTd(tx, block.Hash(), block.NumberU64(), g.Difficulty); err != nil {
		return err
	}
	if err := rawdb.WriteBlock(tx, block); err != nil {
		return err
	}
	if err := rawdbv3.TxNums.WriteForGenesis(tx, 1); err != nil {
		return err
	}
	if err := rawdb.WriteReceipts(tx, block.NumberU64(), nil); err != nil {
		return err
	}

	if err := rawdb.WriteCanonicalHash(tx, block.Hash(), block.NumberU64()); err != nil {
		return err
	}

	rawdb.WriteHeadBlockHash(tx, block.Hash())
	if err := rawdb.WriteHeadHeaderHash(tx, block.Hash()); err != nil {
		return err
	}
	if err := rawdb.WriteChainConfig(tx, block.Hash(), config); err != nil {
		return err
	}
	// We support ethash/serenity for issuance (for now)
	if g.Config.Consensus != chain.EtHashConsensus {
		return nil
	}
	// Issuance is the sum of allocs
	genesisIssuance := big.NewInt(0)
	for _, account := range g.Alloc {
		genesisIssuance.Add(genesisIssuance, account.Balance)
	}

	// BlockReward can be present at genesis
	if block.Header().Difficulty.Cmp(serenity.SerenityDifficulty) == 0 {
		// Proof-of-stake is 0.3 ether per block (TODO: revisit)
		genesisIssuance.Add(genesisIssuance, serenity.RewardSerenity)
	} else {
		blockReward, _ := ethash.AccumulateRewards(g.Config, block.Header(), nil)
		// Set BlockReward
		genesisIssuance.Add(genesisIssuance, blockReward.ToBig())
	}
	if err := rawdb.WriteTotalIssued(tx, 0, genesisIssuance); err != nil {
		return err
	}
	if err := rawdb.WriteTotalBurnt(tx, 0, libcommon.Big0); err != nil {
		return err
	}

	log.Info("genesis block is written to database")

	return nil
}
