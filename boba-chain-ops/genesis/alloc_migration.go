package genesis

import (
	"encoding/json"

	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/core/types"
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
