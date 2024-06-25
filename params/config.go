// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import (
	"embed"
	"encoding/json"
	"fmt"
	"math/big"
	"path"

	"github.com/ledgerwatch/erigon-lib/chain"
	"github.com/ledgerwatch/erigon-lib/chain/networkname"
	libcommon "github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/polygon/bor/borcfg"

	"github.com/ledgerwatch/erigon/common/paths"
)

//go:embed chainspecs
var chainspecs embed.FS

func readChainSpec(filename string) *chain.Config {
	f, err := chainspecs.Open(filename)
	if err != nil {
		panic(fmt.Sprintf("Could not open chainspec for %s: %v", filename, err))
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	spec := &chain.Config{}
	err = decoder.Decode(&spec)
	if err != nil {
		panic(fmt.Sprintf("Could not parse chainspec for %s: %v", filename, err))
	}

	if spec.BorJSON != nil {
		borConfig := &borcfg.BorConfig{}
		err = json.Unmarshal(spec.BorJSON, borConfig)
		if err != nil {
			panic(fmt.Sprintf("Could not parse 'bor' chainspec for %s: %v", filename, err))
		}
		spec.Bor = borConfig
	}

	return spec
}

// Genesis hashes to enforce below configs on.
var (
	MainnetGenesisHash    = libcommon.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
	HoleskyGenesisHash    = libcommon.HexToHash("0xb5f7f912443c940f21fd611f12828d75b534364ed9e95ca4e307729a4661bde4")
	SepoliaGenesisHash    = libcommon.HexToHash("0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9")
	GoerliGenesisHash     = libcommon.HexToHash("0xbf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a")
	MumbaiGenesisHash     = libcommon.HexToHash("0x7b66506a9ebdbf30d32b43c5f15a3b1216269a1ec3a75aa3182b86176a2b1ca7")
	AmoyGenesisHash       = libcommon.HexToHash("0x7202b2b53c5a0836e773e319d18922cc756dd67432f9a1f65352b61f4406c697")
	BorMainnetGenesisHash = libcommon.HexToHash("0xa9c28ce2141b56c474f1dc504bee9b01eb1bd7d1a507580d5519d4437a97de1b")
	BorDevnetGenesisHash  = libcommon.HexToHash("0x5a06b25b0c6530708ea0b98a3409290e39dce6be7f558493aeb6e4b99a172a87")
	GnosisGenesisHash     = libcommon.HexToHash("0x4f1dd23188aab3a76b463e4af801b52b1248ef073c648cbdc4c9333d3da79756")
	ChiadoGenesisHash     = libcommon.HexToHash("0xada44fd8d2ecab8b08f256af07ad3e777f17fb434f8f8e678b312f576212ba9a")

	OPMainnetGenesisHash = libcommon.HexToHash("0x7ca38a1916c42007829c55e69d3e9a73265554b586a499015373241b8a3fa48b")
	OPGoerliGenesisHash  = libcommon.HexToHash("0xc1fc15cd51159b1f1e5cbc4b82e85c1447ddfa33c52cf1d98d14fba0d6354be1")
	OPSepoliaGenesisHash = libcommon.HexToHash("0x102de6ffb001480cc9b8b548fd05c34cd4f46ae4aa91759393db90ea0409887d")

	BobaMainnetGenesisHash = libcommon.HexToHash("0xdcd9e6a8f9973eaa62da2874959cb152faeb4fd6929177bd6335a1a16074ef9c")
	BobaSepoliaGenesisHash = libcommon.HexToHash("0xc6171953a6a376ece6e33149686044f24f58a387ce2636a54e391d330b2326b5")

	BobaBnbTestnetGenesisHash = libcommon.HexToHash("0x4d26ddc947c7cea924d5ef272c1a5ef40a1dce5ca2cbbaccad59d33f2505a30d")
)

var (
	GnosisGenesisStateRoot = libcommon.HexToHash("0x40cf4430ecaa733787d1a65154a3b9efb560c95d9e324a23b97f0609b539133b")
	ChiadoGenesisStateRoot = libcommon.HexToHash("0x9ec3eaf4e6188dfbdd6ade76eaa88289b57c63c9a2cde8d35291d5a29e143d31")
)

var (
	// MainnetChainConfig is the chain parameters to run a node on the main network.
	MainnetChainConfig = readChainSpec("chainspecs/mainnet.json")

	// HoleskyChainConfi contains the chain parameters to run a node on the Holesky test network.
	HoleskyChainConfig = readChainSpec("chainspecs/holesky.json")

	// SepoliaChainConfig contains the chain parameters to run a node on the Sepolia test network.
	SepoliaChainConfig = readChainSpec("chainspecs/sepolia.json")

	// GoerliChainConfig contains the chain parameters to run a node on the Görli test network.
	GoerliChainConfig = readChainSpec("chainspecs/goerli.json")

	// AllProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers into the main net protocol.
	AllProtocolChanges = &chain.Config{
		ChainID:                       big.NewInt(1337),
		Consensus:                     chain.EtHashConsensus,
		HomesteadBlock:                big.NewInt(0),
		TangerineWhistleBlock:         big.NewInt(0),
		SpuriousDragonBlock:           big.NewInt(0),
		ByzantiumBlock:                big.NewInt(0),
		ConstantinopleBlock:           big.NewInt(0),
		PetersburgBlock:               big.NewInt(0),
		IstanbulBlock:                 big.NewInt(0),
		MuirGlacierBlock:              big.NewInt(0),
		BerlinBlock:                   big.NewInt(0),
		LondonBlock:                   big.NewInt(0),
		ArrowGlacierBlock:             big.NewInt(0),
		GrayGlacierBlock:              big.NewInt(0),
		TerminalTotalDifficulty:       big.NewInt(0),
		TerminalTotalDifficultyPassed: true,
		ShanghaiTime:                  big.NewInt(0),
		CancunTime:                    big.NewInt(0),
		Ethash:                        new(chain.EthashConfig),
	}

	// AllCliqueProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers into the Clique consensus.
	AllCliqueProtocolChanges = &chain.Config{
		ChainID:               big.NewInt(1337),
		Consensus:             chain.CliqueConsensus,
		HomesteadBlock:        big.NewInt(0),
		TangerineWhistleBlock: big.NewInt(0),
		SpuriousDragonBlock:   big.NewInt(0),
		ByzantiumBlock:        big.NewInt(0),
		ConstantinopleBlock:   big.NewInt(0),
		PetersburgBlock:       big.NewInt(0),
		IstanbulBlock:         big.NewInt(0),
		MuirGlacierBlock:      big.NewInt(0),
		BerlinBlock:           big.NewInt(0),
		LondonBlock:           big.NewInt(0),
		Clique:                &chain.CliqueConfig{Period: 0, Epoch: 30000},
	}

	MumbaiChainConfig = readChainSpec("chainspecs/mumbai.json")

	AmoyChainConfig = readChainSpec("chainspecs/amoy.json")

	BorMainnetChainConfig = readChainSpec("chainspecs/bor-mainnet.json")

	BorDevnetChainConfig = readChainSpec("chainspecs/bor-devnet.json")

	GnosisChainConfig = readChainSpec("chainspecs/gnosis.json")

	ChiadoChainConfig = readChainSpec("chainspecs/chiado.json")

	CliqueSnapshot = NewSnapshotConfig(10, 1024, 16384, true, "")

	TestChainConfig = &chain.Config{
		ChainID:               big.NewInt(1337),
		Consensus:             chain.EtHashConsensus,
		HomesteadBlock:        big.NewInt(0),
		TangerineWhistleBlock: big.NewInt(0),
		SpuriousDragonBlock:   big.NewInt(0),
		ByzantiumBlock:        big.NewInt(0),
		ConstantinopleBlock:   big.NewInt(0),
		PetersburgBlock:       big.NewInt(0),
		IstanbulBlock:         big.NewInt(0),
		MuirGlacierBlock:      big.NewInt(0),
		BerlinBlock:           big.NewInt(0),
		Ethash:                new(chain.EthashConfig),
	}

	TestChainAuraConfig = &chain.Config{
		ChainID:               big.NewInt(1),
		Consensus:             chain.AuRaConsensus,
		HomesteadBlock:        big.NewInt(0),
		TangerineWhistleBlock: big.NewInt(0),
		SpuriousDragonBlock:   big.NewInt(0),
		ByzantiumBlock:        big.NewInt(0),
		ConstantinopleBlock:   big.NewInt(0),
		PetersburgBlock:       big.NewInt(0),
		IstanbulBlock:         big.NewInt(0),
		MuirGlacierBlock:      big.NewInt(0),
		BerlinBlock:           big.NewInt(0),
		LondonBlock:           big.NewInt(0),
		Aura:                  &chain.AuRaConfig{},
	}

	TestOptimismChainConfig = &chain.Config{
		ChainID:               big.NewInt(1337),
		Consensus:             chain.EtHashConsensus,
		HomesteadBlock:        big.NewInt(0),
		TangerineWhistleBlock: big.NewInt(0),
		SpuriousDragonBlock:   big.NewInt(0),
		ByzantiumBlock:        big.NewInt(0),
		ConstantinopleBlock:   big.NewInt(0),
		PetersburgBlock:       big.NewInt(0),
		IstanbulBlock:         big.NewInt(0),
		MuirGlacierBlock:      big.NewInt(0),
		BerlinBlock:           big.NewInt(0),
		Ethash:                new(chain.EthashConfig),
		Optimism: &chain.OptimismConfig{
			EIP1559Elasticity:  8,
			EIP1559Denominator: 1,
		},
		BedrockBlock: big.NewInt(1000000000000000000),
	}

	TestRules = TestChainConfig.Rules(0, 0)

	// This is an Optimism chain config with bedrock starting a block 5, introduced for historical endpoint testing, largely based on the clique config
	OptimismTestConfig = func() *chain.Config {
		conf := *AllCliqueProtocolChanges // copy the config
		conf.Clique = nil
		conf.TerminalTotalDifficultyPassed = true
		conf.BedrockBlock = big.NewInt(5)
		conf.Optimism = &chain.OptimismConfig{EIP1559Elasticity: 50, EIP1559Denominator: 10}
		return &conf
	}()
)

type ConsensusSnapshotConfig struct {
	CheckpointInterval uint64 // Number of blocks after which to save the vote snapshot to the database
	InmemorySnapshots  int    // Number of recent vote snapshots to keep in memory
	InmemorySignatures int    // Number of recent block signatures to keep in memory
	DBPath             string
	InMemory           bool
}

const cliquePath = "clique"

func NewSnapshotConfig(checkpointInterval uint64, inmemorySnapshots int, inmemorySignatures int, inmemory bool, dbPath string) *ConsensusSnapshotConfig {
	if len(dbPath) == 0 {
		dbPath = paths.DefaultDataDir()
	}

	return &ConsensusSnapshotConfig{
		checkpointInterval,
		inmemorySnapshots,
		inmemorySignatures,
		path.Join(dbPath, cliquePath),
		inmemory,
	}
}

func ChainConfigByChainName(chain string) *chain.Config {
	switch chain {
	case networkname.MainnetChainName:
		return MainnetChainConfig
	case networkname.DevChainName:
		return AllCliqueProtocolChanges
	case networkname.HoleskyChainName:
		return HoleskyChainConfig
	case networkname.SepoliaChainName:
		return SepoliaChainConfig
	case networkname.GoerliChainName:
		return GoerliChainConfig
	case networkname.MumbaiChainName:
		return MumbaiChainConfig
	case networkname.AmoyChainName:
		return AmoyChainConfig
	case networkname.BorMainnetChainName:
		return BorMainnetChainConfig
	case networkname.BorDevnetChainName:
		return BorDevnetChainConfig
	case networkname.GnosisChainName:
		return GnosisChainConfig
	case networkname.ChiadoChainName:
		return ChiadoChainConfig
	default:
		return nil
	}
}

func GenesisHashByChainName(chain string) *libcommon.Hash {
	switch chain {
	case networkname.MainnetChainName:
		return &MainnetGenesisHash
	case networkname.HoleskyChainName:
		return &HoleskyGenesisHash
	case networkname.SepoliaChainName:
		return &SepoliaGenesisHash
	case networkname.GoerliChainName:
		return &GoerliGenesisHash
	case networkname.MumbaiChainName:
		return &MumbaiGenesisHash
	case networkname.AmoyChainName:
		return &AmoyGenesisHash
	case networkname.BorMainnetChainName:
		return &BorMainnetGenesisHash
	case networkname.BorDevnetChainName:
		return &BorDevnetGenesisHash
	case networkname.GnosisChainName:
		return &GnosisGenesisHash
	case networkname.ChiadoChainName:
		return &ChiadoGenesisHash
	case networkname.OPMainnetChainName:
		// cannot use genesis hash from superchain registry because of pre-bedrock blocks
		return &OPMainnetGenesisHash
	case networkname.OPGoerliChainName:
		// cannot use genesis has from superchain registry because of pre-bedrock blocks
		return &OPGoerliGenesisHash
	case networkname.OPSepoliaChainName:
		return &OPSepoliaGenesisHash
	case networkname.BobaMainnetChainName:
		// cannot use genesis hash from superchain registry because of pre-bedrock blocks
		return &BobaMainnetGenesisHash
	case networkname.BobaSepoliaChainName:
		// cannot use genesis hash from superchain registry because of pre-bedrock blocks
		return &BobaSepoliaGenesisHash
	default:
		if opStackChainCfg := OPStackChainConfigByName(chain); opStackChainCfg != nil {
			genesisHash := libcommon.Hash(opStackChainCfg.Genesis.L2.Hash)
			return &genesisHash
		}
		return nil
	}
}

func ChainConfigByGenesisHash(genesisHash libcommon.Hash) *chain.Config {
	if cfg := ChainConfigByOpStackGenesisHash(genesisHash); cfg != nil {
		return cfg
	}
	switch {
	case genesisHash == MainnetGenesisHash:
		return MainnetChainConfig
	case genesisHash == HoleskyGenesisHash:
		return HoleskyChainConfig
	case genesisHash == SepoliaGenesisHash:
		return SepoliaChainConfig
	case genesisHash == GoerliGenesisHash:
		return GoerliChainConfig
	case genesisHash == MumbaiGenesisHash:
		return MumbaiChainConfig
	case genesisHash == AmoyGenesisHash:
		return AmoyChainConfig
	case genesisHash == BorMainnetGenesisHash:
		return BorMainnetChainConfig
	case genesisHash == BorDevnetGenesisHash:
		return BorDevnetChainConfig
	case genesisHash == GnosisGenesisHash:
		return GnosisChainConfig
	case genesisHash == ChiadoGenesisHash:
		return ChiadoChainConfig
	default:
		return nil
	}
}

func NetworkIDByChainName(chain string) uint64 {
	if opStackChainCfg := OPStackChainConfigByName(chain); opStackChainCfg != nil {
		return opStackChainCfg.ChainID
	}
	config := ChainConfigByChainName(chain)
	if config == nil {
		return 0
	}
	return config.ChainID.Uint64()
}

func IsChainPoS(chainConfig *chain.Config, currentTDProvider func() *big.Int) bool {
	return isChainIDPoS(chainConfig.ChainID) || hasChainPassedTerminalTD(chainConfig, currentTDProvider)
}

func isChainIDPoS(chainID *big.Int) bool {
	ids := []*big.Int{
		MainnetChainConfig.ChainID,
		HoleskyChainConfig.ChainID,
		GoerliChainConfig.ChainID,
		SepoliaChainConfig.ChainID,
		GnosisChainConfig.ChainID,
		ChiadoChainConfig.ChainID,
	}
	for _, id := range ids {
		if id.Cmp(chainID) == 0 {
			return true
		}
	}
	return false
}

func hasChainPassedTerminalTD(chainConfig *chain.Config, currentTDProvider func() *big.Int) bool {
	if chainConfig.TerminalTotalDifficultyPassed {
		return true
	}

	terminalTD := chainConfig.TerminalTotalDifficulty
	if terminalTD == nil {
		return false
	}

	currentTD := currentTDProvider()
	return (currentTD != nil) && (terminalTD.Cmp(currentTD) <= 0)
}
