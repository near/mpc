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
    pub home_dir: String,
    /// Hex-encoded 16 byte AES key for local storage encryption.
    pub secret_store_key_hex: String,
    /// If provided, the root keyshare is stored on GCP.
    #[serde(default)]
    pub gcp_keyshare_secret_id: Option<String>,
    #[serde(default)]
    pub gcp_project_id: Option<String>,
    /// TEE authority configuration.
    pub tee_authority: TeeAuthorityStartConfig,
    /// Hex representation of the hash of the running image. Only required in TEE.
    #[serde(default)]
    pub image_hash: Option<String>,
    /// Path to the file where the node writes the latest allowed hash.
    /// If not set, assumes running outside of TEE and skips image hash monitoring.
    #[serde(default)]
    pub latest_allowed_hash_file: Option<PathBuf>,
    /// Hex-encoded 32 byte AES key for backup encryption.
    #[serde(default)]
    pub backup_encryption_key_hex: Option<String>,
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
                let url: Url = quote_upload_url.parse().context("invalid quote_upload_url")?;
                DstackTeeAuthorityConfig::new(dstack_endpoint, url).into()
            }
        })
    }
}

impl StartConfig {
    pub fn from_json_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("failed to parse config file: {}", path.display()))
    }
}
