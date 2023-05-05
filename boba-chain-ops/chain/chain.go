package chain

import (
	"errors"
	"math/big"
)

var (
	BobaGoerliChainId = big.NewInt(2888)
	// Boba Goerli genesis gas limit
	BobaGoerliGenesisGasLimit = 11000000
	// Boba Goerli genesis block coinbase
	BobaGoerliGenesisCoinbase = "0x0000000000000000000000000000000000000000"
	// Boba Goerli genesis block extra data
	BobaGoerliGenesisExtraData = "000000000000000000000000000000000000000000000000000000000000000000000398232e2064f896018496b4b44b3d62751f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	// Boba Goerli genesis block hash
	BobaGoerliGenesisRoot = "0x36c808dc3bb586c14bebde3ca630a4d49a1fdad0b01d7e58f96f2fcd1aa0003d"

	ErrInvalidChainID = errors.New("invalid chain id")
)

func IsBobaValidChainId(chainId *big.Int) bool {
	if BobaGoerliChainId.Cmp(chainId) == 0 {
		return true
	}
	return false
}

func GetBobaGenesisGasLimit(chainId *big.Int) int {
	// Boba Goerli
	if BobaGoerliChainId.Cmp(chainId) == 0 {
		return BobaGoerliGenesisGasLimit
	}
	return 11000000
}

func GetBobaGenesisCoinbase(chainId *big.Int) string {
	// Boba Goerli
	if BobaGoerliChainId.Cmp(chainId) == 0 {
		return BobaGoerliGenesisCoinbase
	}
	return "0x0000000000000000000000000000000000000000"
}

func GetBobaGenesisExtraData(chainId *big.Int) string {
	// Boba Goerli
	if BobaGoerliChainId.Cmp(chainId) == 0 {
		return BobaGoerliGenesisExtraData
	}
	return ""
}

func GetBobaGenesisRoot(chainId *big.Int) string {
	// Boba Goerli
	if BobaGoerliChainId.Cmp(chainId) == 0 {
		return BobaGoerliGenesisRoot
	}
	return ""
}
