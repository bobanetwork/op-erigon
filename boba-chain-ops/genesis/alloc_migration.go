package genesis

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/c2h5oh/datasize"
	"github.com/holiman/uint256"
	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/common"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/kv"
	"github.com/ledgerwatch/erigon-lib/kv/mdbx"
	"github.com/ledgerwatch/erigon/core"
	"github.com/ledgerwatch/erigon/core/state"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/ledgerwatch/log/v3"
	"golang.org/x/exp/slices"
)

// This middle layer is used to convert the genesis account format from geth to erigon
type LegacyGenesisAccount struct {
	Code    string                 `json:"code,omitempty"`
	Storage map[common.Hash]string `json:"storage,omitempty"`
	Nonce   uint64                 `json:"nonce,omitempty"`
}

func MigrateAlloc(bytes []byte) (types.GenesisAlloc, error) {
	var legacyAlloc map[common.Address]LegacyGenesisAccount
	if err := json.Unmarshal(bytes, &legacyAlloc); err != nil {
		return nil, err
	}
	genesisAlloc := make(types.GenesisAlloc)
	for addr, account := range legacyAlloc {
		storage := make(map[common.Hash]common.Hash)
		for k, v := range account.Storage {
			storage[k] = common.HexToHash(v)
		}
		genesisAlloc[addr] = types.GenesisAccount{
			Code:    common.FromHex(account.Code),
			Balance: common.Big0,
			Nonce:   account.Nonce,
			Storage: storage,
		}
	}
	return genesisAlloc, nil
}

var genesisTmpDB kv.RwDB
var genesisDBLock sync.Mutex

// This function is from erigon/core/genesis_write.go
func AllocToGenesis(g *types.Genesis, head *types.Header) (*state.IntraBlockState, error) {
	var statedb *state.IntraBlockState
	wg := sync.WaitGroup{}
	wg.Add(1)

	var err error

	go func() { // we may run inside write tx, can't open 2nd write tx in same goroutine
		// TODO(yperbasis): use memdb.MemoryMutation instead
		defer wg.Done()
		genesisDBLock.Lock()
		defer genesisDBLock.Unlock()
		if genesisTmpDB == nil {
			genesisTmpDB = mdbx.NewMDBX(log.New()).InMem("").MapSize(2 * datasize.GB).MustOpen()
		}
		var tx kv.RwTx
		if tx, err = genesisTmpDB.BeginRw(context.Background()); err != nil {
			return
		}
		defer tx.Rollback()
		r, w := state.NewDbStateReader(tx), state.NewDbStateWriter(tx, 0)
		statedb = state.New(r)

		hasConstructorAllocation := false
		for _, account := range g.Alloc {
			if len(account.Constructor) > 0 {
				hasConstructorAllocation = true
				break
			}
		}
		// See https://github.com/NethermindEth/nethermind/blob/master/src/Nethermind/Nethermind.Consensus.AuRa/InitializationSteps/LoadGenesisBlockAuRa.cs
		if hasConstructorAllocation && g.Config.Aura != nil {
			statedb.CreateAccount(libcommon.Address{}, false)
		}

		keys := sortedAllocKeys(g.Alloc)
		for _, key := range keys {
			addr := libcommon.BytesToAddress([]byte(key))
			account := g.Alloc[addr]

			balance, overflow := uint256.FromBig(account.Balance)
			if overflow {
				panic("overflow at genesis allocs")
			}
			statedb.AddBalance(addr, balance)
			statedb.SetCode(addr, account.Code)
			statedb.SetNonce(addr, account.Nonce)
			for key, value := range account.Storage {
				key := key
				val := uint256.NewInt(0).SetBytes(value.Bytes())
				statedb.SetState(addr, &key, *val)
			}

			if len(account.Constructor) > 0 {
				if _, err = core.SysCreate(addr, account.Constructor, *g.Config, statedb, head, g.ExcessDataGas); err != nil {
					return
				}
			}

			if len(account.Code) > 0 || len(account.Storage) > 0 || len(account.Constructor) > 0 {
				statedb.SetIncarnation(addr, state.FirstContractIncarnation)
			}
		}

		// apply all the changes

		if err = statedb.FinalizeTx(&chain.Rules{}, w); err != nil {
			return
		}
		// We override the root hash with the one from legacy genesis
		// if root, err = trie.CalcRoot("genesis", tx); err != nil {
		// 	return
		// }
	}()

	wg.Wait()

	if err != nil {
		return nil, err
	}

	return statedb, nil
}

func sortedAllocKeys(m types.GenesisAlloc) []string {
	keys := make([]string, len(m))
	i := 0
	for k := range m {
		keys[i] = string(k.Bytes())
		i++
	}
	slices.Sort(keys)
	return keys
}
