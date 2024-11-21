use crate::config::{IndexerConfig, SyncMode};
use near_indexer::near_primitives::types::Gas;

impl IndexerConfig {
    pub(crate) fn to_near_indexer_config(
        &self,
        home_dir: std::path::PathBuf,
    ) -> near_indexer::IndexerConfig {
        near_indexer::IndexerConfig {
            home_dir,
            sync_mode: self.sync_mode.clone().into(),
            await_for_node_synced: if self.stream_while_syncing {
                near_indexer::AwaitForNodeSyncedEnum::StreamWhileSyncing
            } else {
                near_indexer::AwaitForNodeSyncedEnum::WaitForFullSync
            },
            validate_genesis: self.validate_genesis,
        }
    }
}

impl From<SyncMode> for near_indexer::SyncModeEnum {
    fn from(sync_mode: SyncMode) -> Self {
        match sync_mode {
            SyncMode::SyncFromInterruption => Self::FromInterruption,
            SyncMode::SyncFromLatest => Self::LatestSynced,
            SyncMode::SyncFromBlock(args) => Self::BlockHeight(args.height),
        }
    }
}

#[derive(clap::Parser, Debug)]
pub(crate) struct InitConfigArgs {
    /// The directory in which to write the config files
    #[clap(long)]
    pub home_dir: String,
    /// chain/network id (localnet, testnet, devnet, betanet)
    #[clap(short, long)]
    pub chain_id: Option<String>,
    /// Account ID for the validator key
    #[clap(long)]
    pub account_id: Option<String>,
    /// Specify private key generated from seed (TESTING ONLY)
    #[clap(long)]
    pub test_seed: Option<String>,
    /// Number of shards to initialize the chain with
    #[clap(short, long, default_value = "1")]
    pub num_shards: u64,
    /// Makes block production fast (TESTING ONLY)
    #[clap(short, long)]
    pub fast: bool,
    /// Genesis file to use when initialize testnet (including downloading)
    #[clap(short, long)]
    pub genesis: Option<String>,
    #[clap(long)]
    /// Download the verified NEAR genesis file automatically.
    pub download_genesis: bool,
    /// Specify a custom download URL for the genesis-file.
    #[clap(long)]
    pub download_genesis_url: Option<String>,
    /// Specify a custom download URL for the records-file.
    #[clap(long)]
    pub download_records_url: Option<String>,
    #[clap(long)]
    /// Download the verified NEAR config file automatically.
    pub download_config: bool,
    /// Specify a custom download URL for the config file.
    #[clap(long)]
    pub download_config_url: Option<String>,
    /// Specify the boot nodes to bootstrap the network
    pub boot_nodes: Option<String>,
    /// Specify a custom max_gas_burnt_view limit.
    #[clap(long)]
    pub max_gas_burnt_view: Option<Gas>,
}

impl From<InitConfigArgs> for near_indexer::InitConfigArgs {
    fn from(config_args: InitConfigArgs) -> Self {
        Self {
            chain_id: config_args.chain_id,
            account_id: config_args.account_id,
            test_seed: config_args.test_seed,
            num_shards: config_args.num_shards,
            fast: config_args.fast,
            genesis: config_args.genesis,
            download_genesis: config_args.download_genesis,
            download_genesis_url: config_args.download_genesis_url,
            download_records_url: config_args.download_records_url,
            download_config: if config_args.download_config {
                Some(near_config_utils::DownloadConfigType::RPC)
            } else {
                None
            },
            download_config_url: config_args.download_config_url,
            boot_nodes: config_args.boot_nodes,
            max_gas_burnt_view: config_args.max_gas_burnt_view,
        }
    }
}
