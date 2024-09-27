package params

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum-optimism/superchain-registry/superchain"
	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/chain/networkname"
	"github.com/ledgerwatch/erigon-lib/common"
)

const (
	OPMainnetChainID      = 10
	OPSepoliaChainID      = 11155420
	BaseMainnetChainID    = 8453
	baseSepoliaChainID    = 84532
	pgnSepoliaChainID     = 58008
	devnetChainID         = 997
	chaosnetChainID       = 888
	BobaMainnetChainID    = 288
	BobaSepoliaChainID    = 28882
	BobaBnbTestnetChainID = 9728
)

// OP Stack chain config
var (
	// March 17, 2023 @ 7:00:00 pm UTC
	OptimismGoerliRegolithTime = big.NewInt(1679079600)
	// March 5, 2023 @ 2:48:00 am UTC
	devnetRegolithTime = big.NewInt(1677984480)
	// August 16, 2023 @ 3:34:22 am UTC
	chaosnetRegolithTime = big.NewInt(1692156862)
	// Apr Apr 16 2024 21:27:59 UTC 2024
	BobaMainnetRegolithTime = big.NewInt(1713302879)
	// January 18, 2024 @ 5:59:48 pm UTC
	BobaSepoliaRegolithTime = big.NewInt(1705600788)
	// Thu Jun 20 2024 21:49:27 pm UTC
	BobaBnbTestnetRegoTime = big.NewInt(1718920167)
)

// OPStackChainConfigByName loads chain config corresponding to the chain name from superchain registry.
// This implementation is based on optimism monorepo(https://github.com/ethereum-optimism/optimism/blob/op-node/v1.4.1/op-node/chaincfg/chains.go#L59)
func OPStackChainConfigByName(name string) *superchain.ChainConfig {
	// Handle legacy name aliases
	name = networkname.HandleLegacyName(name)
	for _, chainCfg := range superchain.OPChains {
		if strings.EqualFold(chainCfg.Chain+"-"+chainCfg.Superchain, name) {
			return chainCfg
		}
	}
	return nil
}

// OPStackChainConfigByGenesisHash loads chain config corresponding to the genesis hash from superchain registry.
func OPStackChainConfigByGenesisHash(genesisHash common.Hash) *superchain.ChainConfig {
	if bytes.Equal(genesisHash.Bytes(), OPMainnetGenesisHash.Bytes()) {
		return superchain.OPChains[OPMainnetChainID]
	} else if bytes.Equal(genesisHash.Bytes(), OPSepoliaGenesisHash.Bytes()) {
		return superchain.OPChains[OPSepoliaChainID]
	} else if bytes.Equal(genesisHash.Bytes(), BobaSepoliaGenesisHash.Bytes()) {
		return superchain.OPChains[BobaSepoliaChainID]
	} else if bytes.Equal(genesisHash.Bytes(), BobaMainnetGenesisHash.Bytes()) {
		return superchain.OPChains[BobaMainnetChainID]
	} else if bytes.Equal(genesisHash.Bytes(), BobaBnbTestnetGenesisHash.Bytes()) {
		return superchain.OPChains[BobaBnbTestnetChainID]
	}
	for _, chainCfg := range superchain.OPChains {
		if bytes.Equal(chainCfg.Genesis.L2.Hash[:], genesisHash.Bytes()) {
			return chainCfg
		}
	}
	return nil
}

// ChainConfigByOpStackChainName loads chain config corresponding to the chain name from superchain registry, and builds erigon chain config.
func ChainConfigByOpStackChainName(name string) *chain.Config {
	opStackChainCfg := OPStackChainConfigByName(name)
	if opStackChainCfg == nil {
		return nil
	}
	return LoadSuperChainConfig(opStackChainCfg)
}

// ChainConfigByOpStackGenesisHash loads chain config corresponding to the genesis hash from superchain registry, and builds erigon chain config.
func ChainConfigByOpStackGenesisHash(genesisHash common.Hash) *chain.Config {
	opStackChainCfg := OPStackChainConfigByGenesisHash(genesisHash)
	if opStackChainCfg == nil {
		return nil
	}
	return LoadSuperChainConfig(opStackChainCfg)
}

// LoadSuperChainConfig loads superchain config from superchain registry for given chain, and builds erigon chain config.
// This implementation is based on op-geth(https://github.com/ethereum-optimism/op-geth/blob/c7871bc4454ffc924eb128fa492975b30c9c46ad/params/superchain.go#L39)
func LoadSuperChainConfig(opStackChainCfg *superchain.ChainConfig) *chain.Config {
	chConfig, ok := superchain.OPChains[opStackChainCfg.ChainID]
	if !ok {
		panic("unknown superchain: " + fmt.Sprint(opStackChainCfg.ChainID))
	}
	out := &chain.Config{
		ChainName:                     chConfig.Name,
		ChainID:                       new(big.Int).SetUint64(chConfig.ChainID),
		HomesteadBlock:                common.Big0,
		DAOForkBlock:                  nil,
		TangerineWhistleBlock:         common.Big0,
		SpuriousDragonBlock:           common.Big0,
		ByzantiumBlock:                common.Big0,
		ConstantinopleBlock:           common.Big0,
		PetersburgBlock:               common.Big0,
		IstanbulBlock:                 common.Big0,
		MuirGlacierBlock:              common.Big0,
		BerlinBlock:                   common.Big0,
		LondonBlock:                   common.Big0,
		ArrowGlacierBlock:             common.Big0,
		GrayGlacierBlock:              common.Big0,
		MergeNetsplitBlock:            common.Big0,
		ShanghaiTime:                  nil,
		CancunTime:                    nil,
		PragueTime:                    nil,
		BedrockBlock:                  common.Big0,
		RegolithTime:                  big.NewInt(0),
		CanyonTime:                    nil,
		EcotoneTime:                   nil,
		FjordTime:                     nil,
		GraniteTime:                   nil,
		TerminalTotalDifficulty:       common.Big0,
		TerminalTotalDifficultyPassed: true,
		Ethash:                        nil,
		Clique:                        nil,
	}

	if chConfig.CanyonTime != nil {
		out.ShanghaiTime = new(big.Int).SetUint64(*chConfig.CanyonTime) // Shanghai activates with Canyon
		out.CanyonTime = new(big.Int).SetUint64(*chConfig.CanyonTime)
	}
	if chConfig.EcotoneTime != nil {
		out.CancunTime = new(big.Int).SetUint64(*chConfig.EcotoneTime) // CancunTime activates with Ecotone
		out.EcotoneTime = new(big.Int).SetUint64(*chConfig.EcotoneTime)
	}
	if chConfig.FjordTime != nil {
		out.FjordTime = new(big.Int).SetUint64(*chConfig.FjordTime)
	}
	if chConfig.GraniteTime != nil {
		out.GraniteTime = new(big.Int).SetUint64(*chConfig.GraniteTime)
	}
	if chConfig.Optimism != nil {
		out.Optimism = &chain.OptimismConfig{
			EIP1559Elasticity:  chConfig.Optimism.EIP1559Elasticity,
			EIP1559Denominator: chConfig.Optimism.EIP1559Denominator,
		}
		if chConfig.Optimism.EIP1559DenominatorCanyon != nil {
			out.Optimism.EIP1559DenominatorCanyon = *chConfig.Optimism.EIP1559DenominatorCanyon
		}
	}

	// special overrides for OP-Stack chains with pre-Regolith upgrade history
	switch opStackChainCfg.ChainID {
	case OPMainnetChainID:
		out.BerlinBlock = big.NewInt(3950000)
		out.LondonBlock = big.NewInt(105235063)
		out.ArrowGlacierBlock = big.NewInt(105235063)
		out.GrayGlacierBlock = big.NewInt(105235063)
		out.MergeNetsplitBlock = big.NewInt(105235063)
		out.BedrockBlock = big.NewInt(105235063)
	case baseSepoliaChainID:
		out.Optimism.EIP1559Elasticity = 10
	case pgnSepoliaChainID:
		out.Optimism.EIP1559Elasticity = 2
		out.Optimism.EIP1559Denominator = 8
	case devnetChainID:
		out.RegolithTime = devnetRegolithTime
		out.Optimism.EIP1559Elasticity = 10
	case chaosnetChainID:
		out.RegolithTime = chaosnetRegolithTime
		out.Optimism.EIP1559Elasticity = 10
	case BobaSepoliaChainID:
		out.BerlinBlock = big.NewInt(511)
		out.LondonBlock = big.NewInt(511)
		out.ArrowGlacierBlock = big.NewInt(511)
		out.GrayGlacierBlock = big.NewInt(511)
		out.MergeNetsplitBlock = big.NewInt(511)
		out.BedrockBlock = big.NewInt(511)
		out.RegolithTime = BobaSepoliaRegolithTime
	case BobaMainnetChainID:
		out.BerlinBlock = big.NewInt(1149019)
		out.LondonBlock = big.NewInt(1149019)
		out.ArrowGlacierBlock = big.NewInt(1149019)
		out.GrayGlacierBlock = big.NewInt(1149019)
		out.MergeNetsplitBlock = big.NewInt(1149019)
		out.BedrockBlock = big.NewInt(1149019)
		out.RegolithTime = BobaMainnetRegolithTime
	case BobaBnbTestnetChainID:
		out.BerlinBlock = big.NewInt(675077)
		out.LondonBlock = big.NewInt(675077)
		out.ArrowGlacierBlock = big.NewInt(675077)
		out.GrayGlacierBlock = big.NewInt(675077)
		out.MergeNetsplitBlock = big.NewInt(675077)
		out.BedrockBlock = big.NewInt(675077)
		out.RegolithTime = BobaBnbTestnetRegoTime
	}

	return out
}
