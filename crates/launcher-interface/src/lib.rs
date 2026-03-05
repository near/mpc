pub const MPC_IMAGE_HASH_EVENT: &str = "mpc-image-digest";

pub mod types {
    use std::fmt;
    use std::str::FromStr;

    use mpc_primitives::hash::MpcDockerImageHash;
    use serde::{Deserialize, Serialize};

    /// JSON structure for the approved hashes file written by the MPC node, and read by the launcher.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct ApprovedHashesFile {
        pub approved_hashes: bounded_collections::NonEmptyVec<DockerSha256Digest>,
    }

    impl ApprovedHashesFile {
        pub fn newest_approved_hash(&self) -> &DockerSha256Digest {
            self.approved_hashes.first()
        }
    }

    const SHA256_PREFIX: &str = "sha256:";

    #[derive(Debug, Clone, PartialEq, Eq, derive_more::From)]
    pub struct DockerSha256Digest(MpcDockerImageHash);

    impl fmt::Display for DockerSha256Digest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{SHA256_PREFIX}{}", self.0.as_hex())
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum DockerDigestParseError {
        #[error("missing {SHA256_PREFIX} prefix")]
        MissingPrefix,
        #[error(transparent)]
        InvalidHash(#[from] mpc_primitives::hash::Hash32ParseError),
    }

    impl DockerSha256Digest {
        pub fn as_raw_hex(&self) -> String {
            self.0.as_hex()
        }
    }

    impl FromStr for DockerSha256Digest {
        type Err = DockerDigestParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let hex_str = s
                .strip_prefix(SHA256_PREFIX)
                .ok_or(DockerDigestParseError::MissingPrefix)?;
            Ok(DockerSha256Digest(hex_str.parse()?))
        }
    }

    impl Serialize for DockerSha256Digest {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.to_string().serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for DockerSha256Digest {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            s.parse().map_err(serde::de::Error::custom)
        }
    }
}

mod paths {}

#[cfg(test)]
mod tests {
    use super::types::{ApprovedHashesFile, DockerSha256Digest};
    use mpc_primitives::hash::MpcDockerImageHash;

    fn sample_digest() -> DockerSha256Digest {
        let hash: MpcDockerImageHash = [0xab; 32].into();
        DockerSha256Digest::from(hash)
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
        let deserialized: DockerSha256Digest = serde_json::from_str(&serialized).unwrap();
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
        let result = serde_json::from_value::<DockerSha256Digest>(json);
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
        let result = serde_json::from_value::<DockerSha256Digest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_rejects_wrong_length() {
        let json = serde_json::json!("sha256:abab");
        let result = serde_json::from_value::<DockerSha256Digest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn display_docker_digest() {
        let digest = sample_digest();
        insta::assert_snapshot!("docker_digest_display", digest.to_string());
    }

    #[test]
    fn parse_docker_digest() {
        let input = "sha256:abababababababababababababababababababababababababababababababab";
        let parsed: DockerSha256Digest = input.parse().unwrap();
        assert_eq!(parsed.to_string(), input);
    }

    #[test]
    fn parse_rejects_missing_prefix() {
        let result = "abababababababababababababababababababababababababababababababababab"
            .parse::<DockerSha256Digest>();
        assert!(matches!(
            result,
            Err(super::types::DockerDigestParseError::MissingPrefix)
        ));
    }

    #[test]
    fn parse_rejects_invalid_hex() {
        let result = "sha256:not_valid_hex!".parse::<DockerSha256Digest>();
        assert!(matches!(
            result,
            Err(super::types::DockerDigestParseError::InvalidHash(_))
        ));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let result = "sha256:abab".parse::<DockerSha256Digest>();
        assert!(matches!(
            result,
            Err(super::types::DockerDigestParseError::InvalidHash(_))
        ));
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
