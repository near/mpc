use super::ConfigFile;
use anyhow::Context;
use clap::ValueEnum;
use launcher_interface::types::PccsEndpointConfig;
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
    /// PCCS servers used to fetch TDX attestation collateral. Each entry
    /// is a URL plus an optional per-URL TLS trust override. Tried in
    /// order on every fetch; the first one to succeed wins, the rest are
    /// fallbacks. At least one entry is required. Defaults to Phala's
    /// PCCS if the field is omitted.
    ///
    /// Per-URL TLS trust override (the `tls = ...` part of each entry)
    /// lets an operator combine, for example, a self-signed local PCCS
    /// (`tls = { mode = "insecure" }`) with public-CA fallbacks
    /// (`tls` omitted) in the same fallback chain.
    #[serde(default = "default_pccs_endpoints")]
    pub pccs_endpoints: NonEmptyVec<PccsEndpointConfig>,
}

pub fn default_pccs_endpoints() -> NonEmptyVec<PccsEndpointConfig> {
    let url: url::Url = launcher_interface::DEFAULT_PCCS_URL
        .parse()
        .expect("default PCCS URL is valid");
    NonEmptyVec::try_from(vec![PccsEndpointConfig { url, tls: None }])
        .expect("single-element vec is non-empty")
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
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use launcher_interface::types::PccsTlsTrust;

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

    /// A single bare-URL entry (no `tls` override) parses as a one-element
    /// [`NonEmptyVec`] with default trust.
    #[test]
    fn pccs_endpoints__should_parse_single_bare_url_entry() {
        // Given
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            #[serde(default = "default_pccs_endpoints")]
            pccs_endpoints: NonEmptyVec<PccsEndpointConfig>,
        }
        const URL: &str = "https://pccs.example.org/";
        let toml_input = format!(
            r#"
                [[pccs_endpoints]]
                url = "{URL}"
            "#
        );

        // When
        let parsed: Wrapper = toml::from_str(&toml_input).unwrap();
        let entries: Vec<PccsEndpointConfig> = parsed.pccs_endpoints.into_iter().collect();

        // Then
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].url.as_str(), URL);
        assert!(entries[0].tls.is_none());
    }

    /// Multiple entries parse in order; entries with `tls` overrides are
    /// distinguishable from bare entries. Order matters: the fetch path
    /// tries each endpoint in the order the user wrote them.
    #[test]
    fn pccs_endpoints__should_preserve_order_with_mixed_tls_overrides() {
        // Given
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            #[serde(default = "default_pccs_endpoints")]
            pccs_endpoints: NonEmptyVec<PccsEndpointConfig>,
        }
        let toml_input = r#"
            [[pccs_endpoints]]
            url = "https://localhost:8081/"
            tls = { mode = "insecure" }

            [[pccs_endpoints]]
            url = "https://pccs.phala.network/"

            [[pccs_endpoints]]
            url = "https://api.trustedservices.intel.com/"
        "#;

        // When
        let parsed: Wrapper = toml::from_str(toml_input).unwrap();
        let entries: Vec<PccsEndpointConfig> = parsed.pccs_endpoints.into_iter().collect();

        // Then
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].url.as_str(), "https://localhost:8081/");
        assert_matches!(entries[0].tls, Some(PccsTlsTrust::Insecure));
        assert_eq!(entries[1].url.as_str(), "https://pccs.phala.network/");
        assert!(entries[1].tls.is_none());
        assert_eq!(
            entries[2].url.as_str(),
            "https://api.trustedservices.intel.com/"
        );
        assert!(entries[2].tls.is_none());
    }

    /// When the field is omitted altogether, the `#[serde(default)]` hook
    /// returns the Phala default as a single-element vec.
    #[test]
    fn pccs_endpoints__should_default_to_phala_when_omitted() {
        // Given
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            #[serde(default = "default_pccs_endpoints")]
            pccs_endpoints: NonEmptyVec<PccsEndpointConfig>,
        }
        let expected_url: url::Url = launcher_interface::DEFAULT_PCCS_URL.parse().unwrap();

        // When
        let parsed: Wrapper = toml::from_str("").unwrap();
        let entries: Vec<PccsEndpointConfig> = parsed.pccs_endpoints.into_iter().collect();

        // Then
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].url, expected_url);
        assert!(entries[0].tls.is_none());
    }
}
