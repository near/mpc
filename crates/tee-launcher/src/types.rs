use clap::{Parser, ValueEnum};
use mpc_primitives::hash::MpcDockerImageHash;

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
