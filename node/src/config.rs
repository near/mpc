use crate::primitives::ParticipantId;
use anyhow::Context;
use near_crypto::ED25519SecretKey;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Config {
    pub mpc: MpcConfig,
    pub web_ui: WebUIConfig,
    pub indexer: Option<IndexerConfig>,
    pub triple: TripleConfig,
    pub presignature: PresignatureConfig,
    pub signature: SignatureConfig,
    pub secret_storage: SecretStorageConfig,
}

#[derive(Debug)]
pub struct SecretStorageConfig {
    pub data_dir: PathBuf,
    pub aes_key: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TripleConfig {
    pub concurrency: usize,
    pub desired_triples_to_buffer: usize,
    pub timeout_sec: u64,
    /// If we issued a triple generation, wait at least this number of seconds
    /// before issuing another one. This is to avoid thundering herd situations.
    pub parallel_triple_generation_stagger_time_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignatureConfig {
    pub concurrency: usize,
    pub desired_presignatures_to_buffer: usize,
    pub timeout_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureConfig {
    pub timeout_sec: u64,
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
    Interruption,
    /// start from the newest block after node finishes syncing
    Latest,
    /// start from specified block height
    Block(BlockArgs),
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
    pub indexer: Option<IndexerConfig>,
    pub triple: TripleConfig,
    pub presignature: PresignatureConfig,
    pub signature: SignatureConfig,
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

#[derive(Clone, Debug)]
pub struct SecretsConfig {
    pub p2p_private_key: near_crypto::ED25519SecretKey,
}

pub fn load_config(home_dir: &Path, secret_key: [u8; 16]) -> anyhow::Result<Config> {
    let config_path = home_dir.join("config.yaml");
    let file_config = ConfigFile::from_file(&config_path).context("Load config.yaml")?;
    let mpc_config = MpcConfig {
        my_participant_id: file_config.my_participant_id,
        secrets: SecretsConfig {
            p2p_private_key: ED25519SecretKey(
                hex::decode(
                    &std::fs::read_to_string(home_dir.join(&file_config.p2p_private_key_file))
                        .context("Load p2p private key")?,
                )
                .context("Decode p2p private key")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid p2p private key length"))?,
            ),
        },
        participants: file_config.participants,
    };
    let web_config = file_config.web_ui;
    let config = Config {
        mpc: mpc_config,
        web_ui: web_config,
        indexer: file_config.indexer,
        triple: file_config.triple,
        presignature: file_config.presignature,
        signature: file_config.signature,
        secret_storage: SecretStorageConfig {
            data_dir: home_dir.join("data"),
            aes_key: secret_key,
        },
    };
    Ok(config)
}
