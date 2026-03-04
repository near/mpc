use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU16;
use std::path::PathBuf;

use url::Host;

use bounded_collections::NonEmptyVec;
use clap::{Parser, ValueEnum};
use mpc_primitives::hash::MpcDockerImageHash;
use serde::{Deserialize, Serialize};

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
    pub default_image_digest: MpcDockerImageHash,
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
    pub mpc_hash_override: Option<MpcDockerImageHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcBinaryConfig {
    // mpc
    pub mpc_account_id: String,
    pub mpc_local_address: IpAddr,
    pub mpc_secret_key_store: String,
    pub mpc_contract_isd: String,
    pub mpc_env: MpcEnv,
    pub mpc_home_dir: PathBuf,
    pub mpc_responder_id: String,
    pub mpc_backup_encryption_key_hex: String,
    // near
    pub near_boot_nodes: String,
    // rust
    pub rust_backtrace: String,
    pub rust_log: String,
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
    pub fn docker_flag_and_value(&self) -> (String, String) {
        let flag = "--add-host".into();
        let value = self
            .hosts
            .iter()
            .map(|HostEntry { hostname, ip }| format!("{hostname}:{ip}"))
            .collect::<Vec<_>>()
            .join(",");

        (flag, value)
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
    pub fn docker_flag_and_value(&self) -> (String, String) {
        let flag = "-p".into();
        let value = self
            .ports
            .iter()
            .map(|PortMapping { src, dst }| format!("{src}:{dst}"))
            .collect::<Vec<_>>()
            .join(",");

        (flag, value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum MpcEnv {
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

impl MpcBinaryConfig {
    pub fn env_vars(&self) -> Vec<(&'static str, String)> {
        vec![
            ("MPC_ACCOUNT_ID", self.mpc_account_id.clone()),
            ("MPC_LOCAL_ADDRESS", self.mpc_local_address.to_string()),
            ("MPC_SECRET_STORE_KEY", self.mpc_secret_key_store.clone()),
            ("MPC_CONTRACT_ID", self.mpc_contract_isd.clone()),
            ("MPC_ENV", self.mpc_env.to_string()),
            ("MPC_HOME_DIR", self.mpc_home_dir.display().to_string()),
            ("MPC_RESPONDER_ID", self.mpc_responder_id.clone()),
            (
                "MPC_BACKUP_ENCRYPTION_KEY_HEX",
                self.mpc_backup_encryption_key_hex.clone(),
            ),
            ("NEAR_BOOT_NODES", self.near_boot_nodes.clone()),
            ("RUST_BACKTRACE", self.rust_backtrace.clone()),
            ("RUST_LOG", self.rust_log.clone()),
        ]
    }
}
