use launcher_interface::types::DockerSha256Digest;
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum LauncherError {
    #[error("EmitEvent failed while extending RTMR3: {0}")]
    DstackEmitEventFailed(String),

    #[error("MPC_HASH_OVERRIDE invalid: {0}")]
    InvalidHashOverride(String),

    #[error("Image hash not found among tags")]
    ImageHashNotFoundAmongTags,

    #[error("Failed to get auth token from registry: {0}")]
    RegistryAuthFailed(String),

    #[error("docker compose up failed for validated hash")]
    DockerRunFailed {
        image_hash: DockerSha256Digest,
        inner: std::io::Error,
    },

    #[error("docker compose up failed for validated hash")]
    DockerRunFailedExitStatus {
        image_hash: DockerSha256Digest,
        output: String,
    },

    #[error("Failed to read {path}: {source}")]
    FileRead {
        path: String,
        source: std::io::Error,
    },

    #[error("Failed to write {path}: {source}")]
    FileWrite {
        path: String,
        source: std::io::Error,
    },

    #[error("Failed to create temp file: {0}")]
    TempFileCreate(std::io::Error),

    #[error("Failed to parse {path}: {source}")]
    JsonParse {
        path: String,
        source: serde_json::Error,
    },

    #[error("Failed to parse {path}: {source}")]
    TomlParse {
        path: String,
        source: toml::de::Error,
    },

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Registry response parse error: {0}")]
    RegistryResponseParse(String),

    #[error("Invalid manifest URL: {0}")]
    InvalidManifestUrl(String),

    #[error("User config contains reserved key [{0}] — remove it from mpc_node_config")]
    ReservedConfigKey(String),

    #[error("The selected image failed digest validation: {0}")]
    ImageDigestValidationFailed(#[from] ImageDigestValidationFailed),
}

#[derive(Error, Debug)]
pub(crate) enum ImageDigestValidationFailed {
    #[error("manifest digest lookup failed: {0}")]
    ManifestDigestLookupFailed(String),
    #[error("docker pull failed for {0}")]
    DockerPullFailed(String),
    #[error("docker inspect failed for {0}")]
    DockerInspectFailed(String),
    #[error(
        "pulled image has mismatching image ID. pulled: {pulled_image_id}, expected: {expected_image_id}"
    )]
    PulledImageHasMismatchedDigest {
        expected_image_id: DockerSha256Digest,
        pulled_image_id: DockerSha256Digest,
    },
}
