use launcher_interface::types::DockerSha256Digest;
use serde::{Deserialize, Serialize};

/// Partial response https://auth.docker.io/token
#[derive(Debug, Deserialize, Serialize)]
pub struct DockerTokenResponse {
    pub token: String,
}

/// Response from `GET /v2/{name}/manifests/{reference}`.
///
/// The `mediaType` field determines the variant:
/// - OCI image index → multi-platform manifest with a list of platform entries
/// - Docker V2 / OCI manifest → single-platform manifest with a config digest
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "mediaType")]
pub enum ManifestResponse {
    /// Multi-platform manifest (OCI image index).
    #[serde(rename = "application/vnd.oci.image.index.v1+json")]
    ImageIndex { manifests: Vec<ManifestEntry> },

    /// Single-platform Docker V2 manifest.
    #[serde(rename = "application/vnd.docker.distribution.manifest.v2+json")]
    DockerV2 { config: ManifestConfig },

    /// Single-platform OCI manifest.
    #[serde(rename = "application/vnd.oci.image.manifest.v1+json")]
    OciManifest { config: ManifestConfig },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ManifestEntry {
    pub digest: String,
    pub platform: ManifestPlatform,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManifestPlatform {
    pub architecture: String,
    pub os: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ManifestConfig {
    pub digest: DockerSha256Digest,
}
