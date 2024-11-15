use crate::primitives::ParticipantId;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug)]
pub struct Config {
    pub mpc: MpcConfig,
    pub web_ui: WebUIConfig,
    pub triple: TripleConfig,
    pub indexer: Option<IndexerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TripleConfig {
    pub concurrency: usize,
}

#[derive(Debug)]
pub struct MpcConfig {
    pub my_participant_id: ParticipantId,
    pub secrets: SecretsConfig,
    pub participants: ParticipantsConfig,
}

/// Config for the web UI, which is mostly for debugging and metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebUIConfig {
    pub host: String,
    pub port: u16,
}

/// Configures behavior of the near indexer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexerConfig {
    /// Force streaming while node is syncing
    pub stream_while_syncing: bool,
    /// Tells whether to validate the genesis file before starting
    pub validate_genesis: bool,
    /// Sets the starting point for indexing
    pub sync_mode: SyncMode,
    /// Sets the concurrency for indexing
    pub concurrency: std::num::NonZeroU16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncMode {
    /// continue from the block Indexer was interrupted
    SyncFromInterruption,
    /// start from the newest block after node finishes syncing
    SyncFromLatest,
    /// start from specified block height
    SyncFromBlock(BlockArgs),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockArgs {
    /// block height for block sync mode
    pub height: u64,
}

/// The contents of the main config.yaml file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigFile {
    /// The participant ID of this node; it must be one of the IDs in the
    /// participants list.
    pub my_participant_id: ParticipantId,
    /// Contains information about all participants. This MUST BE IDENTICAL
    /// on all nodes.
    pub participants: ParticipantsConfig,
    /// Private key used for the P2P communication's TLS.
    pub p2p_private_key_file: String,
    pub web_ui: WebUIConfig,
    pub triple: TripleConfig,
    pub indexer: Option<IndexerConfig>,
}

impl ConfigFile {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let file = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&file)?;
        Ok(config)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParticipantsConfig {
    /// The threshold for the MPC protocol.
    pub threshold: u32,
    /// Shared private key for signing TLS certificates. It's just to keep the
    /// TLS library happy. We don't rely on CA authentication because we're
    /// hardcoding everyone's public keys.
    pub dummy_issuer_private_key: String,
    pub participants: Vec<ParticipantInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParticipantInfo {
    pub id: ParticipantId,
    /// Address and port that this participant can be directly reached at.
    /// Used for the P2P communication. The protocol required is UDP (QUIC).
    pub address: String,
    pub port: u16,
    /// Public key that corresponds to this P2P peer's private key.
    pub p2p_public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretsConfig {
    pub p2p_private_key: String,
}

pub fn load_config(home_dir: &Path) -> anyhow::Result<Config> {
    let config_path = home_dir.join("config.yaml");
    let file_config = ConfigFile::from_file(&config_path).context("Load config.yaml")?;
    let mpc_config = MpcConfig {
        my_participant_id: file_config.my_participant_id,
        secrets: SecretsConfig {
            p2p_private_key: std::fs::read_to_string(
                home_dir.join(&file_config.p2p_private_key_file),
            )
            .context("Load p2p private key")?,
        },
        participants: file_config.participants,
    };
    let web_config = file_config.web_ui;
    let config = Config {
        mpc: mpc_config,
        web_ui: web_config,
        triple: file_config.triple,
        indexer: file_config.indexer,
    };
    Ok(config)
}
