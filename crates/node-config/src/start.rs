use super::ConfigFile;
use anyhow::Context;
use clap::ValueEnum;
use near_mpc_bounded_collections::NonEmptyVec;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for starting the MPC node. This is the canonical type used
/// by the run logic. Both `StartCmd` (CLI flags) and `StartWithConfigFileCmd`
/// (TOML file) convert into this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartConfig {
    pub home_dir: PathBuf,
    /// Encryption keys and backup settings.
    pub secrets: SecretsStartConfig,
    /// TEE authority and image hash monitoring settings.
    pub tee: launcher_interface::types::TeeConfig,
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
    /// Base URLs of PCCS servers used to fetch TDX attestation collateral.
    /// Tried in order on every fetch; the first one to succeed wins, and the
    /// rest are used only as fallbacks when earlier entries fail. At least
    /// one URL is required. Defaults to Phala's PCCS if the field is omitted.
    #[serde(default = "default_pccs_urls")]
    pub pccs_urls: NonEmptyVec<url::Url>,
}

pub fn default_pccs_urls() -> NonEmptyVec<url::Url> {
    let url: url::Url = launcher_interface::DEFAULT_PCCS_URL
        .parse()
        .expect("default PCCS URL is valid");
    NonEmptyVec::try_from(vec![url]).expect("single-element vec is non-empty")
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

/// NEAR chain / network identifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChainId {
    Mainnet,
    Testnet,
    #[serde(rename = "mpc-localnet")]
    Localnet,
    Sandbox,
    #[serde(untagged)]
    Custom(String),
}

impl ChainId {
    pub fn is_localnet(&self) -> bool {
        matches!(self, ChainId::Localnet | ChainId::Sandbox)
    }

    pub fn to_init_arg(&self) -> Option<String> {
        Some(self.to_string())
    }
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainId::Mainnet => f.write_str("mainnet"),
            ChainId::Testnet => f.write_str("testnet"),
            ChainId::Localnet => f.write_str("mpc-localnet"),
            ChainId::Sandbox => f.write_str("sandbox"),
            ChainId::Custom(s) => f.write_str(s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DownloadConfigType {
    Validator,
    RPC,
    Archival,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tee-launcher blocks the "gcp" key in TEE mode using the hardcoded
    /// string "gcp" (see crates/tee-launcher/src/config.rs).
    /// This test ensures the TOML field name for GCP config is still "gcp".
    /// If this field is renamed, update the launcher's blocked key list too.
    #[test]
    fn gcp_toml_field_name_is_gcp() {
        let gcp = GcpStartConfig {
            keyshare_secret_id: "test".into(),
            project_id: "test".into(),
        };
        let mut table = toml::Table::new();
        table.insert("gcp".to_string(), toml::Value::try_from(&gcp).unwrap());
        let toml_str = toml::to_string(&table).unwrap();
        let parsed: toml::Table = toml::from_str(&toml_str).unwrap();
        assert!(
            parsed.contains_key("gcp"),
            "GCP field name changed — update tee-launcher's TEE-restricted key list"
        );
    }

    /// A single-element TOML array parses as a NonEmptyVec with one entry.
    /// This is the minimum valid form of the `pccs_urls` field.
    #[test]
    fn pccs_urls_accepts_single_element_array() {
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            #[serde(default = "default_pccs_urls")]
            pccs_urls: NonEmptyVec<url::Url>,
        }
        let parsed: Wrapper =
            toml::from_str(r#"pccs_urls = ["https://pccs.example.org"]"#).unwrap();
        let urls: Vec<url::Url> = parsed.pccs_urls.into_iter().collect();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].as_str(), "https://pccs.example.org/");
    }

    /// Multiple entries parse in order. Order matters: the fetch path tries
    /// each URL in the order the user wrote them.
    #[test]
    fn pccs_urls_accepts_multiple_entries_preserving_order() {
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            #[serde(default = "default_pccs_urls")]
            pccs_urls: NonEmptyVec<url::Url>,
        }
        let parsed: Wrapper = toml::from_str(
            r#"
            pccs_urls = [
                "http://localhost:8081",
                "https://pccs.phala.network",
                "https://api.trustedservices.intel.com",
            ]
            "#,
        )
        .unwrap();
        let urls: Vec<url::Url> = parsed.pccs_urls.into_iter().collect();
        assert_eq!(urls.len(), 3);
        assert_eq!(urls[0].as_str(), "http://localhost:8081/");
        assert_eq!(urls[1].as_str(), "https://pccs.phala.network/");
        assert_eq!(urls[2].as_str(), "https://api.trustedservices.intel.com/");
    }

    /// An empty array is explicitly rejected. `NonEmptyVec`'s Deserialize impl
    /// surfaces the bound violation through serde's `custom` error, so the
    /// TOML parser's message mentions the lower-bound problem.
    #[test]
    fn pccs_urls_rejects_empty_array() {
        // `pccs_urls` is never *read* in this test because parsing fails
        // before the struct is constructed; the dead-code lint (rightly)
        // notices. The field exists to give `Wrapper` the same shape as
        // the real `StartConfig::pccs_urls`.
        #[derive(Debug, Deserialize)]
        #[expect(dead_code)]
        struct Wrapper {
            #[serde(default = "default_pccs_urls")]
            pccs_urls: NonEmptyVec<url::Url>,
        }
        let err = toml::from_str::<Wrapper>(r#"pccs_urls = []"#).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("LowerBound") || msg.contains("lower") || msg.contains("1"),
            "expected a non-empty-vec bound error, got: {msg}"
        );
    }

    /// When the field is omitted altogether, the `#[serde(default)]` hook
    /// returns the Phala default as a single-element vec.
    #[test]
    fn pccs_urls_defaults_to_phala_when_omitted() {
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            #[serde(default = "default_pccs_urls")]
            pccs_urls: NonEmptyVec<url::Url>,
        }
        let parsed: Wrapper = toml::from_str("").unwrap();
        let urls: Vec<url::Url> = parsed.pccs_urls.into_iter().collect();
        assert_eq!(urls.len(), 1);
        let expected: url::Url = launcher_interface::DEFAULT_PCCS_URL.parse().unwrap();
        assert_eq!(urls[0], expected);
    }
}
