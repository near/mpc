use launcher_interface::types::DockerSha256Digest;

#[derive(thiserror::Error, Debug)]
pub enum LauncherError {
    #[error("EmitEvent failed while extending RTMR3: {0}")]
    DstackEmitEventFailed(String),

    #[error("MPC_HASH_OVERRIDE invalid: {0}")]
    InvalidHashOverride(String),

    #[error("Invalid image name (must contain only [a-zA-Z0-9/_.-]): {0}")]
    InvalidImageName(String),

    #[error("docker compose up failed for validated hash")]
    DockerRunFailed {
        image_hash: DockerSha256Digest,
        inner: std::io::Error,
    },

    #[error("docker compose up exited with non-zero status for validated hash")]
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

    #[error("User config contains reserved key [{0}] — remove it from mpc_node_config")]
    ReservedConfigKey(String),

    #[error("[{0}] is not allowed in TEE mode")]
    TeeRestrictedConfigKey(String),

    #[error("Image pull failed: {0}")]
    ImageDigestValidationFailed(#[from] ImageDigestValidationFailed),
}

#[derive(thiserror::Error, Debug)]
pub enum ImageDigestValidationFailed {
    #[error("docker pull failed for {reference}: {detail}")]
    DockerPullFailed { reference: String, detail: String },
}
