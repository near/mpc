pub mod foreign_chains;
pub mod start;

pub use foreign_chains::{
    AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig, TokenConfig,
};
pub use start::{
    ChainId, DownloadConfigType, GcpStartConfig, LogConfig, LogFormat, NearInitConfig,
    SecretsStartConfig, StartConfig, default_pccs_urls,
};

use anyhow::Context;
use near_account_id::AccountId;
use near_indexer_primitives::types::Finality;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::Path,
};

const DEFAULT_PPROF_PORT: u16 = 34001;

/// The maximum block-height difference between two nodes before one is
/// considered offline / lagging. Used by the mesh network to filter out
/// participants that are too far behind in the indexer height.
pub const MAX_INDEXER_HEIGHT_DIFF: u64 = 50;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TripleConfig {
    pub concurrency: usize,
    pub desired_triples_to_buffer: usize,
    pub timeout_sec: u64,
    /// If we issued a triple generation, wait at least this number of seconds
    /// before issuing another one. This is to avoid thundering herd situations.
    pub parallel_triple_generation_stagger_time_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresignatureConfig {
    pub concurrency: usize,
    pub desired_presignatures_to_buffer: usize,
    pub timeout_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureConfig {
    pub timeout_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CKDConfig {
    pub timeout_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeygenConfig {
    pub timeout_sec: u64,
}

impl Default for KeygenConfig {
    fn default() -> KeygenConfig {
        KeygenConfig { timeout_sec: 60 }
    }
}

/// Config for the web UI, which is mostly for debugging and metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebUIConfig {
    pub host: String,
    pub port: u16,
}

/// Configures behavior of the near indexer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexerConfig {
    /// Tells whether to validate the genesis file before starting
    pub validate_genesis: bool,
    /// Sets the starting point for indexing
    pub sync_mode: SyncMode,
    /// Sets the finality level at which blocks are streamed
    pub finality: Finality,
    /// Sets the concurrency for indexing
    pub concurrency: std::num::NonZeroU16,
    /// MPC contract id
    pub mpc_contract_id: AccountId,
    /// If specified, replaces the port number in any ParticipantInfos read from chain
    pub port_override: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncMode {
    /// continue from the block Indexer was interrupted
    Interruption,
    /// start from the newest block after node finishes syncing
    Latest,
    /// start from specified block height
    Block(BlockArgs),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockArgs {
    /// block height for block sync mode
    pub height: u64,
}

/// The contents of the on-disk config.yaml file. Contains no secrets.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigFile {
    /// The near account ID that this node owns.
    /// If an on-chain contract is used, this account is used to invoke
    /// identity-sensitive functions of the contract (join, vote, etc.).
    /// If static ParticipantsConfig is specified, this account id is used
    /// to identify our own participant ID from within the static config.
    /// In both cases this account is *not* used to send signature responses.
    pub my_near_account_id: AccountId,

    /// Near account ID of the account that will be used to submit signature responses.
    /// For reference, go to the `spawn_real_indexer` logic.
    pub near_responder_account_id: AccountId,
    /// Number of keys that will be used to sign the signature responses.
    pub number_of_responder_keys: usize,
    // TODO(#2038): remove custom deserializer
    #[serde(deserialize_with = "deserialize_to_socket_addr")]
    pub web_ui: SocketAddr,
    // TODO(#2038): remove custom deserializer
    #[serde(deserialize_with = "deserialize_to_socket_addr")]
    pub migration_web_ui: SocketAddr,
    #[serde(default = "default_pprof_bind_address")]
    pub pprof_bind_address: SocketAddr,
    pub indexer: IndexerConfig,
    pub triple: TripleConfig,
    pub presignature: PresignatureConfig,
    pub signature: SignatureConfig,
    pub ckd: CKDConfig,
    #[serde(default)]
    pub keygen: KeygenConfig,
    #[serde(default)]
    pub foreign_chains: ForeignChainsConfig,
    /// This value is only considered when the node is run in normal node. It defines the number of
    /// working threads for the runtime.
    pub cores: Option<usize>,
}

impl ConfigFile {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let original_config_string =
            fs::read_to_string(path).context("failed to read config file")?;
        let config: Self = serde_yaml::from_str(&original_config_string)?;
        config.validate().context("Validate config.yaml")?;

        // re-serialize if needed
        {
            let re_serialized = serde_yaml::to_string(&config)?;
            let update_config_with_new_schema = re_serialized != original_config_string;

            if update_config_with_new_schema {
                let tmp = path.with_extension("yaml.tmp");
                fs::write(&tmp, re_serialized.as_bytes())?;
                fs::rename(&tmp, path)?;
            }
        }

        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        self.foreign_chains.validate()
    }
}

pub fn load_config_file(home_dir: &Path) -> anyhow::Result<ConfigFile> {
    let config_path = home_dir.join("config.yaml");
    ConfigFile::from_file(&config_path).context("Load config.yaml")
}

fn default_pprof_bind_address() -> SocketAddr {
    (Ipv4Addr::UNSPECIFIED, DEFAULT_PPROF_PORT).into()
}

fn deserialize_to_socket_addr<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let either: either::Either<SocketAddr, WebUIConfig> =
        either::serde_untagged::deserialize(deserializer)?;
    match either {
        either::Either::Left(addr) => Ok(addr),
        either::Either::Right(WebUIConfig { host, port }) => format!("{host}:{port}")
            .to_socket_addrs()
            .map_err(serde::de::Error::custom)?
            .next()
            .ok_or_else(|| serde::de::Error::custom("could not resolve host")),
    }
}
