use super::ConfigFile;
use anyhow::Context;
use clap::ValueEnum;
use launcher_interface::types::{TeeAuthorityConfig, TeeConfig};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tee_authority::tee_authority::{
    DstackTeeAuthorityConfig, LocalTeeAuthorityConfig, TeeAuthority,
};
use url::Url;

/// Configuration for starting the MPC node. This is the canonical type used
/// by the run logic. Both `StartCmd` (CLI flags) and `StartWithConfigFileCmd`
/// (TOML file) convert into this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartConfig {
    pub home_dir: PathBuf,
    /// Encryption keys and backup settings.
    pub secrets: SecretsStartConfig,
    /// TEE authority and image hash monitoring settings.
    pub tee: TeeConfig,
    /// GCP keyshare storage settings. Optional — omit if not using GCP.
    pub gcp: Option<GcpStartConfig>,
    /// NEAR node initialization settings. Required for `start-with-config-file`
    /// so the node can self-initialize when `config.json` is absent.
    /// When using the legacy `start` command (behind `start.sh`), this is
    /// `None` because `start.sh` already ran `mpc-node init`.
    pub near_init: Option<NearInitConfig>,
    /// Node configuration (indexer, protocol parameters, etc.).
    pub node: ConfigFile,
    pub log: LogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub format: LogFormat,
    /// Optional log filter directive (same syntax as `RUST_LOG`).
    /// Examples: `"info"`, `"mpc_node=debug,info"`, `"mpc_node::indexer=trace,warn"`
    /// Falls back to the `RUST_LOG` env var when not set.
    pub filter: Option<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// Plaintext logs
    Plain,
    /// JSON logs
    Json,
}

/// NEAR node initialization configuration. Controls how the NEAR node's
/// genesis and config files are bootstrapped when they don't yet exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearInitConfig {
    pub chain_id: ChainId,
    /// Comma-separated NEAR boot nodes.
    pub boot_nodes: Option<String>,
    /// Path to a local genesis file. When set the genesis is copied from this
    /// path instead of being downloaded. Typically used for localnet.
    pub genesis_path: Option<PathBuf>,
    /// Whether to download the NEAR config file. Defaults to `true` for
    /// non-localnet chains when not specified.
    pub download_config: Option<DownloadConfigType>,
    /// Custom URL to download the NEAR config file from.
    pub download_config_url: Option<String>,
    /// Whether to download the NEAR genesis file. Defaults to `true` for
    /// non-localnet chains when not specified.
    pub download_genesis: bool,
    /// Custom URL to download the genesis file from.
    pub download_genesis_url: Option<String>,
    /// Custom URL to download the genesis records from.
    pub download_genesis_records_url: Option<String>,
    /// Override the NEAR node RPC listen address (e.g. "0.0.0.0:3031").
    /// Useful when running multiple nodes on the same machine.
    pub rpc_addr: Option<String>,
    /// Override the NEAR node network (indexer) listen address (e.g. "0.0.0.0:24568").
    /// Useful when running multiple nodes on the same machine.
    pub network_addr: Option<String>,
}

impl NearInitConfig {
    /// Runs `near_indexer::init_configs` to create the NEAR data directory.
    pub fn run_init(&self, home_dir: &Path) -> anyhow::Result<()> {
        let is_localnet = self.chain_id.is_localnet();
        let genesis_arg = self.genesis_path.as_deref().and_then(Path::to_str);
        let chain_id_arg = self.chain_id.to_init_arg();
        let boot_nodes = self.boot_nodes.as_deref();
        let download_config = self.download_config.clone().map(Into::into);

        near_indexer::init_configs(
            home_dir,
            chain_id_arg,
            None,
            None,
            1,
            false,
            genesis_arg,
            self.download_genesis,
            self.download_genesis_url.as_deref(),
            self.download_genesis_records_url.as_deref(),
            download_config,
            self.download_config_url.as_deref(),
            boot_nodes,
            None,
            None,
        )
        .context("failed to initialize NEAR node")?;

        // For localnet, overwrite the genesis file with the original (init
        // modifies it) and remove the unnecessary validator_key.json.
        if is_localnet {
            if let Some(genesis_src) = &self.genesis_path {
                let genesis_dst = home_dir.join("genesis.json");
                std::fs::copy(genesis_src, &genesis_dst).with_context(|| {
                    format!(
                        "failed to copy genesis from {} to {}",
                        genesis_src.display(),
                        genesis_dst.display()
                    )
                })?;
            }
            let validator_key = home_dir.join("validator_key.json");
            if validator_key.exists() {
                std::fs::remove_file(&validator_key).ok();
            }
        }

        Ok(())
    }
}

/// Encryption keys needed at startup.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretsStartConfig {
    /// Hex-encoded 16 byte AES key for local storage encryption.
    pub secret_store_key_hex: String,
    /// Hex-encoded 32 byte AES key for backup encryption.
    /// If not provided, a key is generated and written to disk.
    #[serde(default)]
    pub backup_encryption_key_hex: Option<String>,
}

impl std::fmt::Debug for SecretsStartConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretsStartConfig")
            .field("secret_store_key_hex", &"[REDACTED]")
            .field(
                "backup_encryption_key_hex",
                &self
                    .backup_encryption_key_hex
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// GCP keyshare storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpStartConfig {
    /// GCP secret ID for storing the root keyshare.
    pub keyshare_secret_id: String,
    /// GCP project ID.
    pub project_id: String,
}

pub trait TeeAuthorityImpl {
    fn into_tee_authority(self) -> anyhow::Result<TeeAuthority>;
}

impl TeeAuthorityImpl for TeeConfig {
    fn into_tee_authority(self) -> anyhow::Result<TeeAuthority> {
        Ok(match self.authority {
            TeeAuthorityConfig::Local => LocalTeeAuthorityConfig::default().into(),
            TeeAuthorityConfig::Dstack {
                dstack_endpoint,
                quote_upload_url,
            } => {
                let url: Url = quote_upload_url
                    .parse()
                    .context("invalid quote_upload_url")?;
                DstackTeeAuthorityConfig::new(dstack_endpoint, url).into()
            }
        })
    }
}

impl StartConfig {
    pub fn from_toml_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let config: Self = toml::from_str(&content)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;
        config
            .node
            .validate()
            .context("invalid node config in config file")?;
        Ok(config)
    }

    /// Ensures the NEAR node data directory is initialized.
    pub fn ensure_near_initialized(&self) -> anyhow::Result<()> {
        let Some(near_init) = &self.near_init else {
            return Ok(());
        };

        let near_config_path = self.home_dir.join("config.json");
        if near_config_path.exists() {
            tracing::info!("NEAR node already initialized, skipping init");
            return Ok(());
        }

        tracing::info!(chain_id = %near_init.chain_id, "initializing NEAR node");
        near_init.run_init(&self.home_dir)?;

        // Patch the NEAR node config the same way start.sh does.
        Self::patch_near_config(&near_config_path, near_init, &self.node)?;

        Ok(())
    }

    /// Applies post-init patches to the NEAR node `config.json`, matching the
    /// behaviour of `update_near_node_config()` in `start.sh`.
    fn patch_near_config(
        config_path: &Path,
        near_init: &NearInitConfig,
        node_config: &ConfigFile,
    ) -> anyhow::Result<()> {
        let raw = std::fs::read_to_string(config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?;

        // TODO(#2453): Deserialize into the `near_core::Config` type (currently not exported)
        let mut config: serde_json::Value =
            serde_json::from_str(&raw).context("failed to parse NEAR config.json")?;

        config["store"]["load_mem_tries_for_tracked_shards"] = serde_json::Value::Bool(true);

        let is_localnet = near_init.chain_id.is_localnet();
        if is_localnet {
            config["state_sync_enabled"] = serde_json::Value::Bool(false);
        } else {
            config["state_sync"]["sync"]["ExternalStorage"]
                ["external_storage_fallback_threshold"] = serde_json::json!(0);
        }

        // Track the shard that hosts the MPC contract.
        let contract_id = node_config.indexer.mpc_contract_id.to_string();
        config["tracked_shards_config"] = serde_json::json!({ "Accounts": [contract_id] });

        // Override listen addresses when running multiple nodes on one machine.
        if let Some(rpc_addr) = &near_init.rpc_addr {
            config["rpc"]["addr"] = serde_json::Value::String(rpc_addr.clone());
        }
        if let Some(network_addr) = &near_init.network_addr {
            config["network"]["addr"] = serde_json::Value::String(network_addr.clone());
        }

        let patched = serde_json::to_string_pretty(&config)
            .context("failed to re-serialize NEAR config.json")?;
        std::fs::write(config_path, patched)
            .with_context(|| format!("failed to write {}", config_path.display()))?;

        tracing::info!("NEAR node config.json patched successfully");
        Ok(())
    }
}

/// NEAR chain / network identifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChainId {
    Mainnet,
    Testnet,
    #[serde(rename = "mpc-localnet")]
    Localnet,
    #[serde(untagged)]
    Custom(String),
}

impl ChainId {
    pub fn is_localnet(&self) -> bool {
        match self {
            ChainId::Localnet => true,
            ChainId::Custom(s) => s == "sandbox",
            _ => false,
        }
    }
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainId::Mainnet => f.write_str("mainnet"),
            ChainId::Testnet => f.write_str("testnet"),
            ChainId::Localnet => f.write_str("mpc-localnet"),
            ChainId::Custom(s) => f.write_str(s),
        }
    }
}

impl ChainId {
    fn to_init_arg(&self) -> Option<String> {
        Some(self.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DownloadConfigType {
    Validator,
    RPC,
    Archival,
}

impl From<DownloadConfigType> for near_config_utils::DownloadConfigType {
    fn from(value: DownloadConfigType) -> Self {
        match value {
            DownloadConfigType::Validator => near_config_utils::DownloadConfigType::Validator,
            DownloadConfigType::RPC => near_config_utils::DownloadConfigType::RPC,
            DownloadConfigType::Archival => near_config_utils::DownloadConfigType::Archival,
        }
    }
}
