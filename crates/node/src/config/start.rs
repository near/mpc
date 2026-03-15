use super::ConfigFile;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tee_authority::tee_authority::{
    DstackTeeAuthorityConfig, LocalTeeAuthorityConfig, TeeAuthority, DEFAULT_DSTACK_ENDPOINT,
    DEFAULT_PHALA_TDX_QUOTE_UPLOAD_URL,
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
    pub tee: TeeStartConfig,
    /// GCP keyshare storage settings. Optional — omit if not using GCP.
    #[serde(default)]
    pub gcp: Option<GcpStartConfig>,
    /// NEAR node initialization settings. Required for `start-with-config-file`
    /// so the node can self-initialize when `config.json` is absent.
    /// When using the legacy `start` command (behind `start.sh`), this is
    /// `None` because `start.sh` already ran `mpc-node init`.
    #[serde(default)]
    pub near_init: Option<NearInitConfig>,
    /// Node configuration (indexer, protocol parameters, etc.).
    pub node: ConfigFile,
}

/// NEAR node initialization configuration. Controls how the NEAR node's
/// genesis and config files are bootstrapped when they don't yet exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearInitConfig {
    /// NEAR chain / network ID (e.g. "mainnet", "testnet", "mpc-localnet").
    pub chain_id: String,
    /// Comma-separated NEAR boot nodes.
    pub boot_nodes: String,
    /// Path to a local genesis file. When set the genesis is copied from this
    /// path instead of being downloaded. Typically used for localnet.
    #[serde(default)]
    pub genesis_path: Option<PathBuf>,
    /// Whether to download the NEAR config file. Defaults to `true` for
    /// non-localnet chains when not specified.
    #[serde(default)]
    pub download_config: Option<bool>,
    /// Custom URL to download the NEAR config file from.
    #[serde(default)]
    pub download_config_url: Option<String>,
    /// Whether to download the NEAR genesis file. Defaults to `true` for
    /// non-localnet chains when not specified.
    #[serde(default)]
    pub download_genesis: Option<bool>,
    /// Custom URL to download the genesis file from.
    #[serde(default)]
    pub download_genesis_url: Option<String>,
    /// Custom URL to download the genesis records from.
    #[serde(default)]
    pub download_genesis_records_url: Option<String>,
}

impl NearInitConfig {
    /// Runs `near_indexer::init_configs` to create the NEAR data directory.
    pub fn run_init(&self, home_dir: &Path) -> anyhow::Result<()> {
        let is_localnet = self.chain_id == "mpc-localnet";

        let genesis_arg = self.genesis_path.as_deref().and_then(Path::to_str);

        let should_download_genesis = self.download_genesis.unwrap_or(!is_localnet);
        let should_download_config = self.download_config.unwrap_or(!is_localnet);

        let download_config_type = if should_download_config {
            Some(near_config_utils::DownloadConfigType::RPC)
        } else {
            None
        };

        let chain_id_arg = if self.chain_id.is_empty() {
            None
        } else {
            Some(self.chain_id.clone())
        };
        let boot_nodes_arg = if self.boot_nodes.is_empty() {
            None
        } else {
            Some(self.boot_nodes.as_str())
        };

        near_indexer::init_configs(
            home_dir,
            chain_id_arg,
            None,
            None,
            1,
            false,
            genesis_arg,
            should_download_genesis,
            self.download_genesis_url.as_deref(),
            self.download_genesis_records_url.as_deref(),
            download_config_type,
            self.download_config_url.as_deref(),
            boot_nodes_arg,
            None, // max_gas_burnt_view
            None, // state_sync_bucket
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

/// TEE-related configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeStartConfig {
    /// TEE authority configuration.
    pub authority: TeeAuthorityStartConfig,
    /// Hex representation of the hash of the running image. Only required in TEE.
    #[serde(default)]
    pub image_hash: Option<String>,
    /// Path to the file where the node writes the latest allowed hash.
    /// If not set, assumes running outside of TEE and skips image hash monitoring.
    #[serde(default)]
    pub latest_allowed_hash_file: Option<PathBuf>,
}

/// GCP keyshare storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpStartConfig {
    /// GCP secret ID for storing the root keyshare.
    pub keyshare_secret_id: String,
    /// GCP project ID.
    pub project_id: String,
}

/// TEE authority configuration for deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TeeAuthorityStartConfig {
    Local,
    Dstack {
        #[serde(default = "default_dstack_endpoint")]
        dstack_endpoint: String,
        #[serde(default = "default_quote_upload_url")]
        // TODO(#2333): use URL type for this type
        quote_upload_url: String,
    },
}

fn default_dstack_endpoint() -> String {
    DEFAULT_DSTACK_ENDPOINT.to_string()
}

fn default_quote_upload_url() -> String {
    DEFAULT_PHALA_TDX_QUOTE_UPLOAD_URL.to_string()
}

impl TeeAuthorityStartConfig {
    pub fn into_tee_authority(self) -> anyhow::Result<TeeAuthority> {
        Ok(match self {
            TeeAuthorityStartConfig::Local => LocalTeeAuthorityConfig::default().into(),
            TeeAuthorityStartConfig::Dstack {
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
    ///
    /// When `near_init` is `Some` and `home_dir/config.json` does not yet
    /// exist, this runs the equivalent of `mpc-node init` followed by the
    /// config-patching that `start.sh` performs (tracked shards, state sync,
    /// etc.).  If `config.json` already exists the method is a no-op.
    ///
    /// When `near_init` is `None` (legacy `start` command) this is always a
    /// no-op — `start.sh` is expected to have handled initialization.
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
        Self::patch_near_config(&near_config_path, &near_init.chain_id, &self.node)?;

        Ok(())
    }

    /// Applies post-init patches to the NEAR node `config.json`, matching the
    /// behaviour of `update_near_node_config()` in `start.sh`.
    fn patch_near_config(
        config_path: &Path,
        chain_id: &str,
        node_config: &ConfigFile,
    ) -> anyhow::Result<()> {
        let raw = std::fs::read_to_string(config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?;
        let mut config: serde_json::Value =
            serde_json::from_str(&raw).context("failed to parse NEAR config.json")?;

        // store.load_mem_tries_for_tracked_shards = true
        config["store"]["load_mem_tries_for_tracked_shards"] = serde_json::Value::Bool(true);

        let is_localnet = chain_id == "mpc-localnet";
        if is_localnet {
            config["state_sync_enabled"] = serde_json::Value::Bool(false);
        } else {
            config["state_sync"]["sync"]["ExternalStorage"]
                ["external_storage_fallback_threshold"] = serde_json::json!(0);
        }

        // Track the shard that hosts the MPC contract.
        let contract_id = node_config.indexer.mpc_contract_id.to_string();
        config["tracked_shards_config"] = serde_json::json!({ "Accounts": [contract_id] });

        let patched = serde_json::to_string_pretty(&config)
            .context("failed to re-serialize NEAR config.json")?;
        std::fs::write(config_path, patched)
            .with_context(|| format!("failed to write {}", config_path.display()))?;

        tracing::info!("NEAR node config.json patched successfully");
        Ok(())
    }
}
