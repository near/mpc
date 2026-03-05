pub const MPC_IMAGE_HASH_EVENT: &str = "mpc-image-digest";

pub mod types {
    use mpc_primitives::hash::MpcDockerImageHash;
    use serde::{Deserialize, Serialize};

    /// JSON structure for the approved hashes file written by the MPC node, and read by the launcher.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct ApprovedHashesFile {
        pub approved_hashes: bounded_collections::NonEmptyVec<DockerDigest>,
    }

    impl ApprovedHashesFile {
        pub fn newest_approved_hash(&self) -> &DockerDigest {
            self.approved_hashes.first()
        }
    }

    const SHA256_PREFIX: &str = "sha256:";

    #[derive(Debug, Clone, derive_more::From)]
    pub struct DockerDigest(MpcDockerImageHash);

    impl Serialize for DockerDigest {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let image_hash_hex = self.0.as_hex();
            let docker_digest_representation = format!("{SHA256_PREFIX}{image_hash_hex}");
            docker_digest_representation.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for DockerDigest {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let hex_str = s.strip_prefix(SHA256_PREFIX).ok_or_else(|| {
                serde::de::Error::custom(format!("missing {SHA256_PREFIX} prefix"))
            })?;

            hex_str
                .parse()
                .map(DockerDigest)
                .map_err(serde::de::Error::custom)
        }
    }
}

mod paths {}

#[cfg(test)]
mod tests {
    use super::types::{ApprovedHashesFile, DockerDigest};
    use mpc_primitives::hash::MpcDockerImageHash;

    fn sample_digest() -> DockerDigest {
        let hash: MpcDockerImageHash = [0xab; 32].into();
        DockerDigest::from(hash)
    }

    #[test]
    fn serialize_docker_digest() {
        let digest = sample_digest();
        let json = serde_json::to_value(&digest).unwrap();
        insta::assert_json_snapshot!("docker_digest", json);
    }

    #[test]
    fn roundtrip_docker_digest() {
        let digest = sample_digest();
        let serialized = serde_json::to_string(&digest).unwrap();
        let deserialized: DockerDigest = serde_json::from_str(&serialized).unwrap();
        insta::assert_json_snapshot!(
            "docker_digest_roundtrip",
            serde_json::to_value(&deserialized).unwrap()
        );
    }

    #[test]
    fn deserialize_rejects_missing_prefix() {
        let json = serde_json::json!(
            "abababababababababababababababababababababababababababababababababab"
        );
        let result = serde_json::from_value::<DockerDigest>(json);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing sha256: prefix"),
            "error should mention missing prefix"
        );
    }

    #[test]
    fn deserialize_rejects_invalid_hex() {
        let json = serde_json::json!("sha256:not_valid_hex!");
        let result = serde_json::from_value::<DockerDigest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_rejects_wrong_length() {
        let json = serde_json::json!("sha256:abab");
        let result = serde_json::from_value::<DockerDigest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn serialize_approved_hashes_file() {
        let file = ApprovedHashesFile {
            approved_hashes: bounded_collections::NonEmptyVec::from_vec(vec![sample_digest()])
                .unwrap(),
        };
        let json = serde_json::to_value(&file).unwrap();
        insta::assert_json_snapshot!("approved_hashes_file", json);
    }
}
