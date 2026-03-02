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
    pub default_image_digest: Option<MpcDockerImageHash>,
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
    /// Remaining env vars forwarded to the MPC container.
    pub mpc_passthrough_env: MpcBinaryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LauncherConfig {
    /// Docker image tags to search (from `MPC_IMAGE_TAGS`, comma-separated).
    pub image_tags: Vec<String>,
    /// Docker image name (from `MPC_IMAGE_NAME`).
    pub image_name: String,
    /// Docker registry (from `MPC_REGISTRY`).
    pub registry: String,
    /// Per-request timeout for registry RPC calls (from `RPC_REQUEST_TIMEOUT_SECS`).
    pub rpc_request_timeout_secs: f64,
    /// Delay between registry RPC retries (from `RPC_REQUEST_INTERVAL_SECS`).
    pub rpc_request_interval_secs: f64,
    /// Maximum registry RPC attempts (from `RPC_MAX_ATTEMPTS`).
    pub rpc_max_attempts: u32,
    /// Optional hash override that bypasses registry lookup (from `MPC_HASH_OVERRIDE`).
    pub mpc_hash_override: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcBinaryConfig {
    // mpc
    mpc_account_id: String,
    mpc_local_address: String,
    mpc_secret_key_store: String,
    mpc_contract_isd: String,
    mpc_env: String,
    mpc_home_dir: String,
    mpc_responder_id: String,
    mpc_backup_encryption_key_hex: String,
    // near
    near_boot_nodes: String,
    // rust
    rust_backtrace: String,
    rust_log: String,
}
