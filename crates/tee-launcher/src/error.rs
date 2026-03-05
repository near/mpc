use launcher_interface::types::DockerSha256Digest;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LauncherError {
    #[error("EmitEvent failed while extending RTMR3: {0}")]
    DstackEmitEventFailed(String),

    #[error("MPC_HASH_OVERRIDE invalid: {0}")]
    InvalidHashOverride(String),

    #[error("Image hash not found among tags")]
    ImageHashNotFoundAmongTags,

    #[error("Failed to get auth token from registry: {0}")]
    RegistryAuthFailed(String),

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
