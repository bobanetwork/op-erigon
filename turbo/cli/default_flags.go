package cli

import (
	"github.com/urfave/cli/v2"

	"github.com/ledgerwatch/erigon/cmd/utils"
)

// DefaultFlags contains all flags that are used and supported by Erigon binary.
var DefaultFlags = []cli.Flag{
	&utils.DataDirFlag,
	&utils.EthashDatasetDirFlag,
	&utils.SnapshotFlag,
	&utils.InternalConsensusFlag,
	&utils.TxPoolDisableFlag,
	&utils.TxPoolLocalsFlag,
	&utils.TxPoolNoLocalsFlag,
	&utils.TxPoolPriceLimitFlag,
	&utils.TxPoolPriceBumpFlag,
	&utils.TxPoolBlobPriceBumpFlag,
	&utils.TxPoolAccountSlotsFlag,
	&utils.TxPoolBlobSlotsFlag,
	&utils.TxPoolGlobalSlotsFlag,
	&utils.TxPoolGlobalBaseFeeSlotsFlag,
	&utils.TxPoolAccountQueueFlag,
	&utils.TxPoolGlobalQueueFlag,
	&utils.TxPoolLifetimeFlag,
	&utils.TxPoolTraceSendersFlag,
	&utils.TxPoolCommitEveryFlag,
	&PruneFlag,
	&PruneHistoryFlag,
	&PruneReceiptFlag,
	&PruneTxIndexFlag,
	&PruneCallTracesFlag,
	&PruneHistoryBeforeFlag,
	&PruneReceiptBeforeFlag,
	&PruneTxIndexBeforeFlag,
	&PruneCallTracesBeforeFlag,
	&BatchSizeFlag,
	&BodyCacheLimitFlag,
	&DatabaseVerbosityFlag,
	&PrivateApiAddr,
	&PrivateApiRateLimit,
	&EtlBufferSizeFlag,
	&TLSFlag,
	&TLSCertFlag,
	&TLSKeyFlag,
	&TLSCACertFlag,
	&StateStreamDisableFlag,
	&SyncLoopThrottleFlag,
	&BadBlockFlag,

	&utils.HTTPEnabledFlag,
	&utils.HTTPServerEnabledFlag,
	&utils.GraphQLEnabledFlag,
	&utils.HTTPListenAddrFlag,
	&utils.HTTPPortFlag,
	&utils.AuthRpcAddr,
	&utils.AuthRpcPort,
	&utils.JWTSecretPath,
	&utils.HttpCompressionFlag,
	&utils.HTTPCORSDomainFlag,
	&utils.HTTPVirtualHostsFlag,
	&utils.AuthRpcVirtualHostsFlag,
	&utils.HTTPApiFlag,
	&utils.WSEnabledFlag,
	&utils.WsCompressionFlag,
	&utils.HTTPTraceFlag,
	&utils.StateCacheFlag,
	&utils.RpcBatchConcurrencyFlag,
	&utils.RpcStreamingDisableFlag,
	&utils.DBReadConcurrencyFlag,
	&utils.RpcAccessListFlag,
	&utils.RpcTraceCompatFlag,
	&utils.RpcGasCapFlag,
	&utils.RpcBatchLimit,
	&utils.RpcReturnDataLimit,
	&utils.AllowUnprotectedTxs,
	&utils.RpcMaxGetProofRewindBlockCount,
	&utils.RPCGlobalTxFeeCapFlag,
	&utils.TxpoolApiAddrFlag,
	&utils.TraceMaxtracesFlag,
	&HTTPReadTimeoutFlag,
	&HTTPWriteTimeoutFlag,
	&HTTPIdleTimeoutFlag,
	&AuthRpcReadTimeoutFlag,
	&AuthRpcWriteTimeoutFlag,
	&AuthRpcIdleTimeoutFlag,
	&EvmCallTimeoutFlag,

	&utils.SnapKeepBlocksFlag,
	&utils.SnapStopFlag,
	&utils.DbPageSizeFlag,
	&utils.DbSizeLimitFlag,
	&utils.ForcePartialCommitFlag,
	&utils.TorrentPortFlag,
	&utils.TorrentMaxPeersFlag,
	&utils.TorrentConnsPerFileFlag,
	&utils.TorrentDownloadSlotsFlag,
	&utils.TorrentStaticPeersFlag,
	&utils.TorrentUploadRateFlag,
	&utils.TorrentDownloadRateFlag,
	&utils.TorrentVerbosityFlag,
	&utils.ListenPortFlag,
	&utils.P2pProtocolVersionFlag,
	&utils.P2pProtocolAllowedPorts,
	&utils.NATFlag,
	&utils.NoDiscoverFlag,
	&utils.DiscoveryV5Flag,
	&utils.NetrestrictFlag,
	&utils.NodeKeyFileFlag,
	&utils.NodeKeyHexFlag,
	&utils.DNSDiscoveryFlag,
	&utils.BootnodesFlag,
	&utils.StaticPeersFlag,
	&utils.TrustedPeersFlag,
	&utils.MaxPeersFlag,
	&utils.ChainFlag,
	&utils.DeveloperPeriodFlag,
	&utils.VMEnableDebugFlag,
	&utils.NetworkIdFlag,
	&utils.FakePoWFlag,
	&utils.GpoBlocksFlag,
	&utils.GpoPercentileFlag,
	&utils.InsecureUnlockAllowedFlag,
	&utils.HistoryV3Flag,
	&utils.IdentityFlag,
	&utils.CliqueSnapshotCheckpointIntervalFlag,
	&utils.CliqueSnapshotInmemorySnapshotsFlag,
	&utils.CliqueSnapshotInmemorySignaturesFlag,
	&utils.CliqueDataDirFlag,
	&utils.MiningEnabledFlag,
	&utils.ProposingDisableFlag,
	&utils.MinerNotifyFlag,
	&utils.MinerGasLimitFlag,
	&utils.MinerEtherbaseFlag,
	&utils.MinerExtraDataFlag,
	&utils.MinerNoVerfiyFlag,
	&utils.MinerSigningKeyFileFlag,
	&utils.SentryAddrFlag,
	&utils.SentryLogPeerInfoFlag,
	&utils.DownloaderAddrFlag,
	&utils.DisableIPV4,
	&utils.DisableIPV6,
	&utils.NoDownloaderFlag,
	&utils.DownloaderVerifyFlag,
	&HealthCheckFlag,
	&utils.HeimdallURLFlag,
	&utils.WebSeedsFlag,
	&utils.WithoutHeimdallFlag,
	&utils.HeimdallgRPCAddressFlag,
	&utils.BorBlockPeriodFlag,
	&utils.BorBlockSizeFlag,
	&utils.WithHeimdallMilestones,
	&utils.EthStatsURLFlag,
	&utils.OverrideCancunFlag,
	&utils.RollupSequencerHTTPFlag,
	&utils.RollupHistoricalRPCFlag,
	&utils.RollupHistoricalRPCTimeoutFlag,
	&utils.RollupDisableTxPoolGossipFlag,
	&utils.HybridComputeEnabledFlag,

	&utils.ConfigFlag,

	&utils.LightClientDiscoveryAddrFlag,
	&utils.LightClientDiscoveryPortFlag,
	&utils.LightClientDiscoveryTCPPortFlag,
	&utils.SentinelAddrFlag,
	&utils.SentinelPortFlag,

	&utils.OtsSearchMaxCapFlag,

	&utils.SilkwormPathFlag,
	&utils.SilkwormExecutionFlag,
	&utils.SilkwormRpcDaemonFlag,
	&utils.SilkwormSentryFlag,

	&utils.TrustedSetupFile,
}
