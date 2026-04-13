use launcher_interface::types::DockerSha256Digest;

#[derive(thiserror::Error, Debug)]
pub enum LauncherError {
    #[error("EmitEvent failed while extending RTMR3: {0}")]
    DstackEmitEventFailed(String),

    #[error("MPC_HASH_OVERRIDE invalid: {0}")]
    InvalidHashOverride(String),

    #[error("Invalid image name (must contain only [a-zA-Z0-9/_.-]): {0}")]
    InvalidImageName(String),

    #[error("No matching image digest found (some tags may have been skipped due to fetch errors)")]
    ImageHashNotFoundAmongTags,

    #[error("config digest mismatch: expected {expected}, got {actual}")]
    ConfigDigestMismatch {
        expected: DockerSha256Digest,
        actual: DockerSha256Digest,
    },

    #[error("Registry authentication/authorization failed: {0}")]
    RegistryAuthFailed(String),

    #[error("Manifest not found: {0}")]
    ManifestNotFound(String),

    #[error("Registry server error: {0}")]
    RegistryServerError(String),

    #[error("Registry request failed: {0}")]
    RegistryRequestFailed(String),

    #[error("Registry error: {0}")]
    RegistryError(String),

    #[error("Invalid image reference: {0}")]
    InvalidImageReference(String),

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

    #[error("Registry response parse error: {0}")]
    RegistryResponseParse(String),

    #[error("User config contains reserved key [{0}] — remove it from mpc_node_config")]
    ReservedConfigKey(String),

    #[error("[{0}] is not allowed in TEE mode — it could be used to exfiltrate key material")]
    TeeRestrictedConfigKey(String),

    #[error("The selected image failed digest validation: {0}")]
    ImageDigestValidationFailed(#[from] ImageDigestValidationFailed),
}

#[derive(thiserror::Error, Debug)]
pub enum ImageDigestValidationFailed {
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
