package networkname

const (
	MainnetChainName        = "mainnet"
	HoleskyChainName        = "holesky"
	SepoliaChainName        = "sepolia"
	GoerliChainName         = "goerli"
	DevChainName            = "dev"
	MumbaiChainName         = "mumbai"
	AmoyChainName           = "amoy"
	BorMainnetChainName     = "bor-mainnet"
	BorDevnetChainName      = "bor-devnet"
	GnosisChainName         = "gnosis"
	BorE2ETestChain2ValName = "bor-e2e-test-2Val"
	ChiadoChainName         = "chiado"

	OPMainnetChainName = "op-mainnet"
	OPGoerliChainName  = "op-goerli"
	OPSepoliaChainName = "op-sepolia"

	BobaMainnetChainName = "boba-mainnet"
	BobaSepoliaChainName = "boba-sepolia"

	LegacyOPMainnetChainName = "optimism-mainnet"
	LegacyOPGoerliChainName  = "optimism-goerli"
	LegacyOPSepoliaChainName = "optimism-sepolia"
)

var All = []string{
	MainnetChainName,
	HoleskyChainName,
	SepoliaChainName,
	GoerliChainName,
	MumbaiChainName,
	AmoyChainName,
	BorMainnetChainName,
	BorDevnetChainName,
	GnosisChainName,
	ChiadoChainName,

	OPMainnetChainName,
	OPSepoliaChainName,
	OPGoerliChainName,

	BobaMainnetChainName,
	BobaSepoliaChainName,
}

func HandleLegacyName(name string) string {
	switch name {
	case LegacyOPGoerliChainName:
		return OPGoerliChainName
	case LegacyOPSepoliaChainName:
		return OPSepoliaChainName
	case LegacyOPMainnetChainName:
		return OPMainnetChainName
	default:
		return name
	}
}
