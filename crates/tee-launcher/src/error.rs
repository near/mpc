use std::path::PathBuf;

use launcher_interface::types::DockerSha256Digest;
use mpc_primitives::hash::DockerSha256Digest;
use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub enum LauncherError {
    #[error("PLATFORM=TEE requires dstack unix socket at {0}")]
    DstackSocketMissing(String),

    #[error("GetQuote failed before extending RTMR3: {0}")]
    DstackGetQuoteFailed(String),

    #[error("EmitEvent failed while extending RTMR3: {0}")]
    DstackEmitEventFailed(String),

    #[error("DEFAULT_IMAGE_DIGEST invalid: {0}")]
    InvalidDefaultDigest(String),

    #[error("Invalid JSON in {path}: approved_hashes missing or empty")]
    InvalidApprovedHashes { path: String },

    #[error("MPC_HASH_OVERRIDE invalid: {0}")]
    InvalidHashOverride(String),

    #[error("Image hash not found among tags")]
    ImageHashNotFoundAmongTags,

    #[error("Failed to get auth token from registry: {0}")]
    RegistryAuthFailed(String),

    #[error("Failed to get successful response from {url} after {attempts} attempts")]
    RegistryRequestFailed { url: Url, attempts: u32 },

    #[error("Digest mismatch: pulled {pulled} != expected {expected}")]
    DigestMismatch { pulled: String, expected: String },

    #[error("MPC image hash validation failed: {0}")]
    ImageValidationFailed(String),

    #[error("docker run failed for validated hash")]
    DockerRunFailed {
        image_hash: DockerSha256Digest,
        inner: std::io::Error,
    },

    #[error("docker run failed for validated hash")]
    DockerRunFailedExitStatus { image_hash: DockerSha256Digest },

    #[error("Too many env vars to pass through (>{0})")]
    TooManyEnvVars(usize),

    #[error("Total env payload too large (>{0} bytes)")]
    EnvPayloadTooLarge(usize),

    #[error("Env var '{key}' has unsafe value: {reason}")]
    UnsafeEnvValue { key: String, reason: String },

    #[error("Unsafe docker command: LD_PRELOAD detected")]
    LdPreloadDetected,

    #[error("Failed to read {path}: {source}")]
    FileRead {
        path: String,
        source: std::io::Error,
    },

    #[error("Failed to parse {path}: {source}")]
    JsonParse {
        path: String,
        source: serde_json::Error,
    },

    #[error("Required environment variable not set: {0}")]
    MissingEnvVar(String),

    #[error("Invalid value for {key}: {value}")]
    InvalidEnvVar { key: String, value: String },

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Registry response parse error: {0}")]
    RegistryResponseParse(String),

    #[error("Invalid manifest URL: {0}")]
    InvalidManifestUrl(String),

    #[error("The selected image failed digest validation: {0}")]
    ImageDigestValidationFailed(#[from] ImageDigestValidationFailed),
}

#[derive(Error, Debug)]
pub enum ImageDigestValidationFailed {
    #[error("manifest digest lookup failed: {0}")]
    ManifestDigestLookupFailed(String),
    #[error("docker pull failed for {0}")]
    DockerPullFailed(String),
    #[error("docker inspect failed for {0}")]
    DockerInspectFailed(String),
    #[error(
        "pulled image has mismatching digest. pulled: {pulled_digest}, expected: {expected_digest}"
    )]
    PulledImageHasMismatchedDigest {
        expected_digest: DockerSha256Digest,
        pulled_digest: DockerSha256Digest,
    },
}
