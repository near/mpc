use super::ConfigFile;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tee_authority::tee_authority::{
    DstackTeeAuthorityConfig, LocalTeeAuthorityConfig, TeeAuthority, DEFAULT_DSTACK_ENDPOINT,
    DEFAULT_PHALA_TDX_QUOTE_UPLOAD_URL,
};
use url::Url;

/// Configuration for starting the MPC node. This is the canonical type used
/// by the run logic. Both `StartCmd` (CLI flags) and `StartWithConfigFileCmd`
/// (JSON file) convert into this type.
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
    /// Node configuration (indexer, protocol parameters, etc.).
    pub node: ConfigFile,
}

/// Encryption keys needed at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsStartConfig {
    /// Hex-encoded 16 byte AES key for local storage encryption.
    pub secret_store_key_hex: String,
    /// Hex-encoded 32 byte AES key for backup encryption.
    /// If not provided, a key is generated and written to disk.
    #[serde(default)]
    pub backup_encryption_key_hex: Option<String>,
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

/// TEE authority configuration for JSON deserialization.
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
    pub fn from_json_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let config: Self = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;
        config
            .node
            .validate()
            .context("invalid node config in config file")?;
        Ok(config)
    }
}
