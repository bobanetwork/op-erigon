package genesis

import (
	"math/big"
	"testing"

	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/boba-bindings/predeploys"
	"github.com/ledgerwatch/erigon/core/types"
	"github.com/stretchr/testify/require"
)

func TestWipePredeployStorage(t *testing.T) {
	g := &types.Genesis{
		Config: &chain.Config{
			ChainID: big.NewInt(2888),
		},
		Alloc: types.GenesisAlloc{},
	}

	code := []byte{1, 2, 3}
	storeVal := common.Hash{31: 0xff}
	nonce := 100

	for _, addr := range predeploys.Predeploys {
		a := *addr
		g.Alloc[a] = types.GenesisAccount{
			Code: code,
			Storage: map[common.Hash]common.Hash{
				storeVal: storeVal,
			},
			Nonce: uint64(nonce),
		}
	}

	WipePredeployStorage(g)

	for _, addr := range predeploys.Predeploys {
		if FrozenStoragePredeploys[*addr] {
			expected := types.GenesisAccount{
				Code: code,
				Storage: map[common.Hash]common.Hash{
					storeVal: storeVal,
				},
				Nonce: uint64(nonce),
			}
			require.Equal(t, expected, g.Alloc[*addr])
			continue
		}
		expected := types.GenesisAccount{
			Code:    code,
			Storage: map[common.Hash]common.Hash{},
			Nonce:   uint64(nonce),
		}
		require.Equal(t, expected, g.Alloc[*addr])
	}
}
