use super::ConfigFile;
use anyhow::Context;
use clap::ValueEnum;
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
    /// Base URL of the PCCS server used to fetch TDX attestation collateral.
    /// Defaults to Phala's PCCS if not set in config.
    #[serde(default = "default_pccs_url")]
    pub pccs_url: url::Url,

    /// Optional PEM-encoded TLS root certificate for the PCCS server.
    /// Set this when pointing at a local PCCS that uses a self-signed cert.
    /// The cert is added as an additional trust anchor; the default trust
    /// roots still work for other endpoints.
    ///
    /// Mutually exclusive with [`pccs_tls_insecure`](Self::pccs_tls_insecure)
    /// — startup rejects setting both.
    #[serde(default)]
    pub pccs_ca_cert_pem: Option<String>,

    /// Disable TLS certificate verification for the PCCS server. **Loopback
    /// only**: startup rejects this flag for `pccs_url` hosts other than
    /// `localhost`, anything in `127.0.0.0/8`, IPv6 loopback `::1` (written
    /// as `https://[::1]:<port>/` in the URL), or the QEMU slirp gateway
    /// `10.0.2.2`. The guardrail prevents silent disablement of TLS
    /// validation against a real network endpoint.
    ///
    /// Acceptable for production deployments where the PCCS runs on the same
    /// host as the CVM (the host is the effective trust boundary; an
    /// attacker capable of swapping the cert already has host-level access).
    /// Use [`pccs_ca_cert_pem`](Self::pccs_ca_cert_pem) instead when a
    /// properly-formed cert is available — same security posture on
    /// loopback, plus a positive operational check that the cert matches
    /// what the operator expects.
    ///
    /// Mutually exclusive with `pccs_ca_cert_pem` — startup rejects setting
    /// both.
    #[serde(default)]
    pub pccs_tls_insecure: bool,
}

pub fn default_pccs_url() -> url::Url {
    launcher_interface::DEFAULT_PCCS_URL
        .parse()
        .expect("default PCCS URL is valid")
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

    /// Two complementary checks on the PCCS-TLS knobs:
    ///
    /// 1. `mem::offset_of!` calls on `StartConfig` — these fail to compile
    ///    if the fields are renamed (or removed) on `StartConfig`. Cheap
    ///    field-existence guarantee for free.
    /// 2. A local `Probe` struct with the same field names exercises serde
    ///    deserialization, default values, and serialization-output
    ///    contains-the-expected-keys. This guards the *probe* against
    ///    accidental drift in the test itself.
    ///
    /// What this doesn't catch: a future `#[serde(rename = "...")]` on
    /// `StartConfig`'s fields would slip past this. To catch that we'd need
    /// to round-trip a real `StartConfig` instance, which currently requires
    /// constructing all the non-default fields on `StartConfig` (dstack
    /// endpoint, log config, indexer config, etc.) — significantly more
    /// fixture for marginal value over the `offset_of!` rename guard.
    #[test]
    #[expect(non_snake_case)]
    fn pccs_tls_fields__should_use_expected_toml_names() {
        // Compile-time check: a rename on StartConfig fails these lines.
        let _ = std::mem::offset_of!(StartConfig, pccs_ca_cert_pem);
        let _ = std::mem::offset_of!(StartConfig, pccs_tls_insecure);

        // Given an isolated struct that has only the two fields we care about,
        // populated from the canonical TOML strings.
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Probe {
            #[serde(default)]
            pccs_ca_cert_pem: Option<String>,
            #[serde(default)]
            pccs_tls_insecure: bool,
        }

        let toml_input = r#"
pccs_ca_cert_pem = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+w==\n-----END CERTIFICATE-----"
pccs_tls_insecure = true
"#;

        // When deserializing
        let probe: Probe = toml::from_str(toml_input).expect("TOML parses");

        // Then both fields are populated as named
        assert!(probe.pccs_tls_insecure);
        assert!(
            probe
                .pccs_ca_cert_pem
                .as_deref()
                .is_some_and(|s| s.contains("BEGIN CERTIFICATE"))
        );

        // And: omitting them yields the documented defaults (None / false).
        let probe_default: Probe = toml::from_str("").expect("empty TOML parses");
        assert_eq!(
            probe_default,
            Probe {
                pccs_ca_cert_pem: None,
                pccs_tls_insecure: false,
            }
        );

        // Probe round-trip stays consistent.
        let serialized = toml::to_string(&Probe {
            pccs_ca_cert_pem: Some("x".into()),
            pccs_tls_insecure: true,
        })
        .unwrap();
        assert!(serialized.contains("pccs_ca_cert_pem"));
        assert!(serialized.contains("pccs_tls_insecure"));
    }
}
