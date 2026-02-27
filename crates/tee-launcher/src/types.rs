use clap::{Parser, ValueEnum};
use serde::Deserialize;

/// CLI arguments parsed from environment variables via clap.
#[derive(Parser, Debug)]
#[command(name = "tee-launcher")]
pub struct CliArgs {
    /// Platform mode: TEE or NONTEE
    #[arg(long, env = "PLATFORM")]
    pub platform: Platform,

    /// Must be set to "1" to enable Docker Content Trust
    #[arg(long, env = "DOCKER_CONTENT_TRUST", default_value = "")]
    pub docker_content_trust: String,

    /// Fallback image digest when the approved-hashes file is absent
    #[arg(long, env = "DEFAULT_IMAGE_DIGEST")]
    pub default_image_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Platform {
    #[value(name = "TEE")]
    Tee,
    #[value(name = "NONTEE")]
    NonTee,
}

#[derive(Debug, Clone)]
pub struct RpcTimingConfig {
    pub request_timeout_secs: f64,
    pub request_interval_secs: f64,
    pub max_attempts: u32,
}

#[derive(Debug, Clone)]
pub struct ImageSpec {
    pub tags: Vec<String>,
    pub image_name: String,
    pub registry: String,
}

#[derive(Debug, Clone)]
pub struct ResolvedImage {
    pub spec: ImageSpec,
    pub digest: String,
}

/// JSON structure for the approved hashes file written by the MPC node.
/// Must stay aligned with `crates/node/src/tee/allowed_image_hashes_watcher.rs`.
#[derive(Debug, Deserialize)]
pub struct ApprovedHashesFile {
    pub approved_hashes: Vec<String>,
}
