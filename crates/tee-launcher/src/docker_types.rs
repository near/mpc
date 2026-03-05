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

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    fn sample_digest_str() -> String {
        format!("sha256:{}", "ab".repeat(32))
    }

    #[test]
    fn image_index_deserializes() {
        // given
        let json = serde_json::json!({
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "digest": "sha256:abc123",
                    "platform": { "architecture": "amd64", "os": "linux" }
                },
                {
                    "digest": "sha256:def456",
                    "platform": { "architecture": "arm64", "os": "linux" }
                }
            ]
        });

        // when
        let result = serde_json::from_value::<ManifestResponse>(json);

        // then
        assert_matches!(result, Ok(ManifestResponse::ImageIndex { manifests }) => {
            assert_eq!(manifests.len(), 2);
            assert_eq!(manifests[0].platform, ManifestPlatform {
                architecture: "amd64".into(),
                os: "linux".into(),
            });
        });
    }

    #[test]
    fn docker_v2_manifest_deserializes() {
        // given
        let json = serde_json::json!({
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": { "digest": sample_digest_str() }
        });

        // when
        let result = serde_json::from_value::<ManifestResponse>(json);

        // then
        assert_matches!(result, Ok(ManifestResponse::DockerV2 { config }) => {
            assert_eq!(config.digest.to_string(), sample_digest_str());
        });
    }

    #[test]
    fn oci_manifest_deserializes() {
        // given
        let json = serde_json::json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "digest": sample_digest_str() }
        });

        // when
        let result = serde_json::from_value::<ManifestResponse>(json);

        // then
        assert_matches!(result, Ok(ManifestResponse::OciManifest { config }) => {
            assert_eq!(config.digest.to_string(), sample_digest_str());
        });
    }

    #[test]
    fn unknown_media_type_is_rejected() {
        // given
        let json = serde_json::json!({
            "mediaType": "application/vnd.unknown.format",
            "config": { "digest": sample_digest_str() }
        });

        // when
        let result = serde_json::from_value::<ManifestResponse>(json);

        // then
        assert_matches!(result, Err(_));
    }

    #[test]
    fn docker_token_response_deserializes() {
        // given
        let json = serde_json::json!({ "token": "abc.def.ghi" });

        // when
        let result = serde_json::from_value::<DockerTokenResponse>(json);

        // then
        assert_matches!(result, Ok(resp) => {
            assert_eq!(resp.token, "abc.def.ghi");
        });
    }
}
