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

    /// PCCS TLS trust policy. When omitted, the node uses the system
    /// trust roots — the default behaviour for `pccs.phala.network`,
    /// `api.trustedservices.intel.com`, etc. Set the `[mpc_node_config.pccs_tls]`
    /// sub-table (with `mode = "ca_cert_pem"` or `mode = "insecure"`)
    /// when pointing at a local PCCS that uses a self-signed cert.
    ///
    /// The two operator modes are mutually exclusive *by construction*:
    /// the underlying type is a tagged enum
    /// ([`PccsTlsTrust`](launcher_interface::types::PccsTlsTrust)), so
    /// at most one can be set in any given config. See that type's
    /// docs for the full mode descriptions and rationale. Per pbeza's
    /// review on PR #3026 this replaces a previous pair of fields
    /// (`pccs_ca_cert_pem` + `pccs_tls_insecure`) that required runtime
    /// mutual-exclusivity validation.
    ///
    /// Loopback-only enforcement on the `Insecure` variant still
    /// happens at startup — that gate is orthogonal to the type
    /// encoding (it depends on `pccs_url`, which the type doesn't
    /// know about).
    #[serde(default)]
    pub pccs_tls: Option<launcher_interface::types::PccsTlsTrust>,
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
    use assert_matches::assert_matches;

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

    /// Two complementary checks on the PCCS-TLS knob:
    ///
    /// 1. `mem::offset_of!(StartConfig, pccs_tls)` — fails to compile
    ///    if the field is renamed (or removed) on `StartConfig`. Cheap
    ///    field-existence guarantee for free.
    /// 2. A local `Probe` struct with the same field name exercises serde
    ///    deserialization (both variants of `PccsTlsTrust`), default
    ///    behaviour (no `[pccs_tls]` table → `None`), and that the
    ///    serialized form keeps the expected `mode` tag.
    ///
    /// What this doesn't catch: a future `#[serde(rename = "...")]` on
    /// `StartConfig`'s field would slip past this. To catch that we'd need
    /// to round-trip a real `StartConfig` instance, which currently requires
    /// constructing all the non-default fields on `StartConfig` (dstack
    /// endpoint, log config, indexer config, etc.) — significantly more
    /// fixture for marginal value over the `offset_of!` rename guard.
    #[test]
    #[expect(non_snake_case)]
    fn pccs_tls_field__should_use_expected_toml_names() {
        use launcher_interface::types::PccsTlsTrust;

        // Compile-time check: a rename on StartConfig fails this line.
        let _ = std::mem::offset_of!(StartConfig, pccs_tls);

        // Given an isolated struct that has only the field we care about,
        // populated from the canonical TOML strings.
        #[derive(Serialize, Deserialize, Debug)]
        struct Probe {
            #[serde(default)]
            pccs_tls: Option<PccsTlsTrust>,
        }

        // ca_cert_pem variant — TOML form must round-trip.
        let toml_pem = r#"
[pccs_tls]
mode = "ca_cert_pem"
ca_cert_pem = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+w==\n-----END CERTIFICATE-----"
"#;
        let probe: Probe = toml::from_str(toml_pem).expect("TOML parses");
        assert_matches!(
            probe.pccs_tls,
            Some(PccsTlsTrust::CaCertPem { ref ca_cert_pem })
                if ca_cert_pem.contains("BEGIN CERTIFICATE")
        );

        // insecure variant — unit form, no extra fields.
        let toml_insecure = r#"
[pccs_tls]
mode = "insecure"
"#;
        let probe: Probe = toml::from_str(toml_insecure).expect("TOML parses");
        assert_matches!(probe.pccs_tls, Some(PccsTlsTrust::Insecure));

        // Empty TOML yields the documented default (None).
        let probe_default: Probe = toml::from_str("").expect("empty TOML parses");
        assert!(probe_default.pccs_tls.is_none());

        // Mutual exclusivity is now a parse-time guarantee: setting both
        // mode-specific fields is rejected by serde because only one
        // variant can match. We don't need a dedicated test for it —
        // the type system enforces it.

        // Round-trip stays consistent (struct field name matches the
        // expected TOML key, after `[pccs_tls]` table header).
        let serialized = toml::to_string(&Probe {
            pccs_tls: Some(PccsTlsTrust::CaCertPem {
                ca_cert_pem: "x".into(),
            }),
        })
        .unwrap();
        assert!(serialized.contains("[pccs_tls]"));
        assert!(serialized.contains("mode = \"ca_cert_pem\""));
        assert!(serialized.contains("ca_cert_pem"));
    }
}
