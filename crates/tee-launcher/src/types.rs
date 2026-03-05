use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU16;
use std::path::PathBuf;

use launcher_interface::types::DockerSha256Digest;
use url::Host;

use bounded_collections::NonEmptyVec;
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::env_validation;

/// CLI arguments parsed from environment variables via clap.
#[derive(Parser, Debug)]
#[command(name = "tee-launcher")]
pub struct CliArgs {
    /// Platform mode: TEE or NONTEE
    #[arg(long, env = "PLATFORM")]
    pub platform: Platform,

    #[arg(long, env = "DOCKER_CONTENT_TRUST")]
    // ensure that `docker_content_trust` is enabled.
    docker_content_trust: DockerContentTrust,

    /// Fallback image digest when the approved-hashes file is absent
    #[arg(long, env = "DEFAULT_IMAGE_DIGEST")]
    pub default_image_digest: DockerSha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DockerContentTrust {
    #[value(name = "1")]
    Enabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Platform {
    #[value(name = "TEE")]
    Tee,
    #[value(name = "NONTEE")]
    NonTee,
}

/// Typed representation of the dstack user config file (`/tapp/user_config`).
///
/// Launcher-only keys are extracted into typed fields; all remaining keys are
/// kept in `passthrough_env` for forwarding to the MPC container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub launcher_config: LauncherConfig,
    pub docker_command_config: DockerLaunchFlags,
    /// Remaining env vars forwarded to the MPC container.
    pub mpc_passthrough_env: MpcBinaryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LauncherConfig {
    /// Docker image tags to search (from `MPC_IMAGE_TAGS`, comma-separated).
    pub image_tags: NonEmptyVec<String>,
    /// Docker image name (from `MPC_IMAGE_NAME`).
    pub image_name: String,
    /// Docker registry (from `MPC_REGISTRY`).
    pub registry: String,
    /// Per-request timeout for registry RPC calls (from `RPC_REQUEST_TIMEOUT_SECS`).
    pub rpc_request_timeout_secs: u64,
    /// Delay between registry RPC retries (from `RPC_REQUEST_INTERVAL_SECS`).
    pub rpc_request_interval_secs: u64,
    /// Maximum registry RPC attempts (from `RPC_MAX_ATTEMPTS`).
    pub rpc_max_attempts: u32,
    /// Optional hash override that bypasses registry lookup (from `MPC_HASH_OVERRIDE`).
    pub mpc_hash_override: Option<DockerSha256Digest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcBinaryConfig {
    // mpc
    // TODO: use near type to not accept any string
    pub mpc_account_id: String,
    pub mpc_local_address: IpAddr,
    // TODO: think this is no longer needed with node generated keys
    pub mpc_secret_key_store: String,
    // TODO: think this is no longer needed with node generated keys
    pub mpc_backup_encryption_key_hex: String,
    pub mpc_env: MpcEnv,
    pub mpc_home_dir: PathBuf,
    // TODO: use near type to not accept any string
    pub mpc_contract_id: String,
    // TODO: use near type to not accept any string
    pub mpc_responder_id: String,
    // near
    pub near_boot_nodes: String,
    // rust
    pub rust_backtrace: RustBacktrace,
    pub rust_log: RustLog,
    /// Additional env vars not covered by the typed fields above.
    /// Allows operators to pass new `MPC_*` vars without a launcher rebuild.
    /// Keys and values are validated at emission time in `env_vars()`.
    #[serde(flatten)]
    pub extra_env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerLaunchFlags {
    pub extra_hosts: ExtraHosts,
    pub port_mappings: PortMappings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExtraHosts {
    hosts: Vec<HostEntry>,
}

impl ExtraHosts {
    /// Returns `["--add-host", "h1:ip1", "--add-host", "h2:ip2", ...]`.
    pub fn docker_args(&self) -> Vec<String> {
        self.hosts
            .iter()
            .flat_map(|HostEntry { hostname, ip }| {
                ["--add-host".into(), format!("{hostname}:{ip}")]
            })
            .collect()
    }
}

/// A `--add-host` entry: `hostname:IPv4`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEntry {
    pub hostname: Host<String>,
    pub ip: Ipv4Addr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PortMappings {
    pub ports: Vec<PortMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapping {
    src: NonZeroU16,
    dst: NonZeroU16,
}

impl PortMappings {
    /// Returns `["-p", "src1:dst1", "-p", "src2:dst2", ...]`.
    pub fn docker_args(&self) -> Vec<String> {
        self.ports
            .iter()
            .flat_map(|PortMapping { src, dst }| ["-p".into(), format!("{src}:{dst}")])
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MpcEnv {
    Localnet,
    Testnet,
    Mainnet,
}

impl fmt::Display for MpcEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcEnv::Localnet => write!(f, "localnet"),
            MpcEnv::Testnet => write!(f, "testnet"),
            MpcEnv::Mainnet => write!(f, "mainnet"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RustBacktrace {
    #[serde(rename = "0")]
    Disabled,
    #[serde(rename = "1")]
    Enabled,
    #[serde(rename = "short")]
    Short,
    #[serde(rename = "full")]
    Full,
}

impl fmt::Display for RustBacktrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RustBacktrace::Disabled => write!(f, "0"),
            RustBacktrace::Enabled => write!(f, "1"),
            RustBacktrace::Short => write!(f, "short"),
            RustBacktrace::Full => write!(f, "full"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RustLogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl fmt::Display for RustLogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RustLogLevel::Error => write!(f, "error"),
            RustLogLevel::Warn => write!(f, "warn"),
            RustLogLevel::Info => write!(f, "info"),
            RustLogLevel::Debug => write!(f, "debug"),
            RustLogLevel::Trace => write!(f, "trace"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RustLog {
    Level(RustLogLevel),
    Filter(String),
}

impl fmt::Display for RustLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RustLog::Level(level) => level.fmt(f),
            RustLog::Filter(filter) => write!(f, "{filter}"),
        }
    }
}

impl MpcBinaryConfig {
    /// Returns all env vars to pass to the MPC container.
    ///
    /// Typed fields are emitted first (deterministic order), followed by
    /// validated extras from `extra_env`. All keys and values are validated
    /// uniformly before returning.
    #[cfg(test)]
    pub(crate) fn with_extra_env(mut self, extra: std::collections::BTreeMap<String, String>) -> Self {
        self.extra_env = extra;
        self
    }

    pub fn env_vars(&self) -> Result<Vec<(String, String)>, crate::error::LauncherError> {
        let mut vars: Vec<(String, String)> = vec![
            ("MPC_ACCOUNT_ID".into(), self.mpc_account_id.clone()),
            (
                "MPC_LOCAL_ADDRESS".into(),
                self.mpc_local_address.to_string(),
            ),
            (
                "MPC_SECRET_STORE_KEY".into(),
                self.mpc_secret_key_store.clone(),
            ),
            ("MPC_CONTRACT_ID".into(), self.mpc_contract_id.clone()),
            ("MPC_ENV".into(), self.mpc_env.to_string()),
            (
                "MPC_HOME_DIR".into(),
                self.mpc_home_dir.display().to_string(),
            ),
            ("MPC_RESPONDER_ID".into(), self.mpc_responder_id.clone()),
            (
                "MPC_BACKUP_ENCRYPTION_KEY_HEX".into(),
                self.mpc_backup_encryption_key_hex.clone(),
            ),
            ("NEAR_BOOT_NODES".into(), self.near_boot_nodes.clone()),
            ("RUST_BACKTRACE".into(), self.rust_backtrace.to_string()),
            ("RUST_LOG".into(), self.rust_log.to_string()),
        ];

        // Keys already emitted via typed fields — skip duplicates from extra_env.
        let typed_keys: std::collections::HashSet<String> =
            vars.iter().map(|(k, _)| k.clone()).collect();

        if self.extra_env.len() > env_validation::MAX_PASSTHROUGH_ENV_VARS {
            return Err(crate::error::LauncherError::TooManyEnvVars(
                env_validation::MAX_PASSTHROUGH_ENV_VARS,
            ));
        }

        // BTreeMap iteration is sorted, giving deterministic output.
        for (key, value) in &self.extra_env {
            if typed_keys.contains(key.as_str()) {
                continue;
            }
            env_validation::validate_env_key(key)?;
            vars.push((key.clone(), value.clone()));
        }

        // Validate ALL env vars uniformly (typed + extra) and enforce aggregate caps.
        let mut total_bytes: usize = 0;
        for (key, value) in &vars {
            env_validation::validate_env_value(key, value)?;
            total_bytes += key.len() + 1 + value.len();
        }
        if total_bytes > env_validation::MAX_TOTAL_ENV_BYTES {
            return Err(crate::error::LauncherError::EnvPayloadTooLarge(
                env_validation::MAX_TOTAL_ENV_BYTES,
            ));
        }

        Ok(vars)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU16;

    use super::*;

    fn base_mpc_config() -> MpcBinaryConfig {
        MpcBinaryConfig {
            mpc_account_id: "test-account".into(),
            mpc_local_address: "127.0.0.1".parse().unwrap(),
            mpc_secret_key_store: "secret".into(),
            mpc_backup_encryption_key_hex: "0".repeat(64),
            mpc_env: MpcEnv::Testnet,
            mpc_home_dir: "/data".into(),
            mpc_contract_id: "contract.near".into(),
            mpc_responder_id: "responder-1".into(),
            near_boot_nodes: "boot1,boot2".into(),
            rust_backtrace: RustBacktrace::Enabled,
            rust_log: RustLog::Level(RustLogLevel::Info),
            extra_env: BTreeMap::new(),
        }
    }

    // --- HostEntry deserialization ---

    #[test]
    fn host_entry_valid_deserialization() {
        // given
        let json =
            serde_json::json!({"hostname": {"Domain": "node.local"}, "ip": "192.168.1.1"});

        // when
        let result = serde_json::from_value::<HostEntry>(json);

        // then
        assert_matches!(result, Ok(entry) => {
            assert_eq!(entry.ip, Ipv4Addr::new(192, 168, 1, 1));
        });
    }

    #[test]
    fn host_entry_rejects_invalid_ip() {
        // given
        let json =
            serde_json::json!({"hostname": {"Domain": "node.local"}, "ip": "not-an-ip"});

        // when
        let result = serde_json::from_value::<HostEntry>(json);

        // then
        assert_matches!(result, Err(_));
    }

    #[test]
    fn host_entry_rejects_plain_string_as_hostname() {
        // given - url::Host requires tagged variant, plain string is rejected
        let json = serde_json::json!({"hostname": "node.local", "ip": "192.168.1.1"});

        // when
        let result = serde_json::from_value::<HostEntry>(json);

        // then
        assert_matches!(result, Err(_));
    }

    #[test]
    fn host_entry_rejects_injection_string_as_hostname() {
        // given
        let json = serde_json::json!({"hostname": "--env LD_PRELOAD=hack.so", "ip": "192.168.1.1"});

        // when
        let result = serde_json::from_value::<HostEntry>(json);

        // then
        assert_matches!(result, Err(_));
    }

    // --- PortMapping deserialization ---

    #[test]
    fn port_mapping_valid_deserialization() {
        // given
        let json = serde_json::json!({"src": 11780, "dst": 11780});

        // when
        let result = serde_json::from_value::<PortMapping>(json);

        // then
        assert_matches!(result, Ok(_));
    }

    #[test]
    fn port_mapping_rejects_zero_port() {
        // given
        let json = serde_json::json!({"src": 0, "dst": 11780});

        // when
        let result = serde_json::from_value::<PortMapping>(json);

        // then
        assert_matches!(result, Err(_));
    }

    #[test]
    fn port_mapping_rejects_out_of_range_port() {
        // given
        let json = serde_json::json!({"src": 65536, "dst": 11780});

        // when
        let result = serde_json::from_value::<PortMapping>(json);

        // then
        assert_matches!(result, Err(_));
    }

    // --- docker_args output format ---

    #[test]
    fn extra_hosts_docker_args_format() {
        // given
        let hosts = ExtraHosts {
            hosts: vec![HostEntry {
                hostname: url::Host::Domain("node.local".into()),
                ip: Ipv4Addr::new(192, 168, 1, 1),
            }],
        };

        // when
        let args = hosts.docker_args();

        // then
        assert_eq!(args, vec!["--add-host", "node.local:192.168.1.1"]);
    }

    #[test]
    fn empty_extra_hosts_produces_no_docker_args() {
        // given
        let hosts = ExtraHosts { hosts: vec![] };

        // when
        let args = hosts.docker_args();

        // then
        assert!(args.is_empty());
    }

    #[test]
    fn port_mappings_docker_args_format() {
        // given
        let mappings = PortMappings {
            ports: vec![PortMapping {
                src: NonZeroU16::new(11780).unwrap(),
                dst: NonZeroU16::new(11780).unwrap(),
            }],
        };

        // when
        let args = mappings.docker_args();

        // then
        assert_eq!(args, vec!["-p", "11780:11780"]);
    }

    // --- MpcBinaryConfig::env_vars ---

    #[test]
    fn env_vars_includes_all_typed_fields() {
        // given
        let config = base_mpc_config();

        // when
        let vars = config.env_vars().unwrap();

        // then
        let keys: Vec<&str> = vars.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"MPC_ACCOUNT_ID"));
        assert!(keys.contains(&"MPC_LOCAL_ADDRESS"));
        assert!(keys.contains(&"MPC_SECRET_STORE_KEY"));
        assert!(keys.contains(&"MPC_CONTRACT_ID"));
        assert!(keys.contains(&"MPC_ENV"));
        assert!(keys.contains(&"MPC_HOME_DIR"));
        assert!(keys.contains(&"MPC_RESPONDER_ID"));
        assert!(keys.contains(&"MPC_BACKUP_ENCRYPTION_KEY_HEX"));
        assert!(keys.contains(&"NEAR_BOOT_NODES"));
        assert!(keys.contains(&"RUST_BACKTRACE"));
        assert!(keys.contains(&"RUST_LOG"));
    }

    #[test]
    fn env_vars_passes_valid_extra_mpc_key() {
        // given
        let mut extra = BTreeMap::new();
        extra.insert("MPC_NEW_FEATURE".into(), "enabled".into());
        let config = base_mpc_config().with_extra_env(extra);

        // when
        let vars = config.env_vars().unwrap();

        // then
        assert!(vars.iter().any(|(k, v)| k == "MPC_NEW_FEATURE" && v == "enabled"));
    }

    #[test]
    fn env_vars_deduplicates_typed_key_from_extra() {
        // given
        let mut extra = BTreeMap::new();
        extra.insert("MPC_ACCOUNT_ID".into(), "duplicate".into());
        let config = base_mpc_config().with_extra_env(extra);

        // when
        let vars = config.env_vars().unwrap();

        // then
        let account_values: Vec<&str> = vars
            .iter()
            .filter(|(k, _)| k == "MPC_ACCOUNT_ID")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(account_values.len(), 1);
        assert_eq!(account_values[0], "test-account");
    }

    #[test]
    fn env_vars_rejects_sensitive_key_in_extra() {
        // given
        let mut extra = BTreeMap::new();
        extra.insert("MPC_P2P_PRIVATE_KEY".into(), "secret".into());
        let config = base_mpc_config().with_extra_env(extra);

        // when
        let result = config.env_vars();

        // then
        assert_matches!(result, Err(crate::error::LauncherError::UnsafeEnvValue { .. }));
    }

    #[test]
    fn env_vars_rejects_account_sk_in_extra() {
        // given
        let mut extra = BTreeMap::new();
        extra.insert("MPC_ACCOUNT_SK".into(), "secret".into());
        let config = base_mpc_config().with_extra_env(extra);

        // when
        let result = config.env_vars();

        // then
        assert_matches!(result, Err(crate::error::LauncherError::UnsafeEnvValue { .. }));
    }

    #[test]
    fn env_vars_rejects_value_with_newline() {
        // given
        let mut extra = BTreeMap::new();
        extra.insert("MPC_INJECTED".into(), "ok\nbad".into());
        let config = base_mpc_config().with_extra_env(extra);

        // when
        let result = config.env_vars();

        // then
        assert_matches!(result, Err(crate::error::LauncherError::UnsafeEnvValue { .. }));
    }

    #[test]
    fn env_vars_rejects_value_containing_ld_preload() {
        // given
        let mut extra = BTreeMap::new();
        extra.insert("MPC_INJECTED".into(), "LD_PRELOAD=/tmp/x.so".into());
        let config = base_mpc_config().with_extra_env(extra);

        // when
        let result = config.env_vars();

        // then
        assert_matches!(result, Err(crate::error::LauncherError::UnsafeEnvValue { .. }));
    }

    #[test]
    fn env_vars_rejects_too_many_extra_vars() {
        // given
        let mut extra = BTreeMap::new();
        for i in 0..=crate::env_validation::MAX_PASSTHROUGH_ENV_VARS {
            extra.insert(format!("MPC_X_{i}"), "1".into());
        }
        let config = base_mpc_config().with_extra_env(extra);

        // when
        let result = config.env_vars();

        // then
        assert_matches!(result, Err(crate::error::LauncherError::TooManyEnvVars(_)));
    }

    #[test]
    fn env_vars_rejects_total_bytes_exceeded() {
        // given
        let mut extra = BTreeMap::new();
        for i in 0..40 {
            extra.insert(
                format!("MPC_BIG_{i}"),
                "a".repeat(crate::env_validation::MAX_ENV_VALUE_LEN),
            );
        }
        let config = base_mpc_config().with_extra_env(extra);

        // when
        let result = config.env_vars();

        // then
        assert_matches!(result, Err(crate::error::LauncherError::EnvPayloadTooLarge(_)));
    }

    #[test]
    fn env_vars_rejects_unknown_non_mpc_key() {
        // given
        let mut extra = BTreeMap::new();
        extra.insert("BAD_KEY".into(), "value".into());
        let config = base_mpc_config().with_extra_env(extra);

        // when
        let result = config.env_vars();

        // then
        assert_matches!(result, Err(crate::error::LauncherError::UnsafeEnvValue { .. }));
    }

    // --- Config full deserialization ---

    #[test]
    fn config_deserializes_valid_json() {
        // given
        let json = serde_json::json!({
            "launcher_config": {
                "image_tags": ["tag1"],
                "image_name": "nearone/mpc-node",
                "registry": "registry.hub.docker.com",
                "rpc_request_timeout_secs": 10,
                "rpc_request_interval_secs": 1,
                "rpc_max_attempts": 20,
                "mpc_hash_override": null
            },
            "docker_command_config": {
                "extra_hosts": {"hosts": [{"hostname": {"Domain": "node1"}, "ip": "192.168.1.1"}]},
                "port_mappings": {"ports": [{"src": 11780, "dst": 11780}]}
            },
            "mpc_passthrough_env": {
                "mpc_account_id": "account123",
                "mpc_local_address": "127.0.0.1",
                "mpc_secret_key_store": "secret",
                "mpc_backup_encryption_key_hex": "0000000000000000000000000000000000000000000000000000000000000000",
                "mpc_env": "Testnet",
                "mpc_home_dir": "/data",
                "mpc_contract_id": "contract.near",
                "mpc_responder_id": "responder-1",
                "near_boot_nodes": "boot1",
                "rust_backtrace": "1",
                "rust_log": "info"
            }
        });

        // when
        let result = serde_json::from_value::<Config>(json);

        // then
        assert_matches!(result, Ok(config) => {
            assert_eq!(config.mpc_passthrough_env.mpc_account_id, "account123");
            assert_eq!(config.launcher_config.image_name, "nearone/mpc-node");
        });
    }

    #[test]
    fn config_rejects_missing_required_field() {
        // given - mpc_account_id is missing
        let json = serde_json::json!({
            "launcher_config": {
                "image_tags": ["tag1"],
                "image_name": "nearone/mpc-node",
                "registry": "registry.hub.docker.com",
                "rpc_request_timeout_secs": 10,
                "rpc_request_interval_secs": 1,
                "rpc_max_attempts": 20,
                "mpc_hash_override": null
            },
            "docker_command_config": {
                "extra_hosts": {"hosts": []},
                "port_mappings": {"ports": []}
            },
            "mpc_passthrough_env": {
                "mpc_local_address": "127.0.0.1",
                "mpc_secret_key_store": "secret",
                "mpc_backup_encryption_key_hex": "0000000000000000000000000000000000000000000000000000000000000000",
                "mpc_env": "Testnet",
                "mpc_home_dir": "/data",
                "mpc_contract_id": "contract.near",
                "mpc_responder_id": "responder-1",
                "near_boot_nodes": "boot1",
                "rust_backtrace": "1",
                "rust_log": "info"
            }
        });

        // when
        let result = serde_json::from_value::<Config>(json);

        // then
        assert_matches!(result, Err(_));
    }
}
