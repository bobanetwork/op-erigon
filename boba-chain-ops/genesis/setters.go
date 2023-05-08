package genesis

import (
	"fmt"

	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/boba-bindings/predeploys"
	"github.com/ledgerwatch/erigon/core/types"

	"github.com/ethereum/go-ethereum/log"
)

// UntouchableCodeHashes contains code hashes of all the contracts
// that should not be touched by the migration process.
type ChainHashMap map[uint64]common.Hash

// TODO: ADD BOBA Token and other ones
var (
	// UntouchablePredeploys are addresses in the predeploy namespace
	// that should not be touched by the migration process.
	UntouchablePredeploys = map[common.Address]bool{
		predeploys.GovernanceTokenAddr: true,
		predeploys.WETH9Addr:           true,
	}

	// UntouchableCodeHashes represent the bytecode hashes of contracts
	// that should not be touched by the migration process.
	UntouchableCodeHashes = map[common.Address]ChainHashMap{
		predeploys.GovernanceTokenAddr: {
			1: common.HexToHash("0x8551d935f4e67ad3c98609f0d9f0f234740c4c4599f82674633b55204393e07f"),
			5: common.HexToHash("0xc4a213cf5f06418533e5168d8d82f7ccbcc97f27ab90197c2c051af6a4941cf9"),
		},
		predeploys.WETH9Addr: {
			1: common.HexToHash("0x779bbf2a738ef09d961c945116197e2ac764c1b39304b2b4418cd4e42668b173"),
			5: common.HexToHash("0x779bbf2a738ef09d961c945116197e2ac764c1b39304b2b4418cd4e42668b173"),
		},
	}

	// FrozenStoragePredeploys represents the set of predeploys that
	// will not have their storage wiped during the migration process.
	// It is very explicitly set in its own mapping to ensure that
	// changes elsewhere in the codebase do no alter the predeploys
	// that do not have their storage wiped. It is safe for all other
	// predeploys to have their storage wiped.
	FrozenStoragePredeploys = map[common.Address]bool{
		predeploys.GovernanceTokenAddr:     true,
		predeploys.WETH9Addr:               true,
		predeploys.LegacyMessagePasserAddr: true,
		predeploys.LegacyERC20ETHAddr:      true,
		predeploys.DeployerWhitelistAddr:   true,
	}
)

// WipePredeployStorage will wipe the storage of all L2 predeploys expect
// for predeploys that must not have their storage altered.
func WipePredeployStorage(g *types.Genesis) error {
	for name, addr := range predeploys.Predeploys {
		if addr == nil {
			return fmt.Errorf("nil address in predeploys mapping for %s", name)
		}

		if FrozenStoragePredeploys[*addr] {
			log.Trace("skipping wiping of storage", "name", name, "address", *addr)
			continue
		}

		log.Info("wiping storage", "name", name, "address", *addr)

		genesisAccount := types.GenesisAccount{
			Constructor: g.Alloc[*addr].Constructor,
			Code:        g.Alloc[*addr].Code,
			Storage:     map[common.Hash]common.Hash{},
			Balance:     g.Alloc[*addr].Balance, // This should be zero
			Nonce:       g.Alloc[*addr].Nonce,
		}
		g.Alloc[*addr] = genesisAccount
	}

	return nil
}
