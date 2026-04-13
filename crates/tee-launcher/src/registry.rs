use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};
use launcher_interface::types::DockerSha256Digest;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::errors::OciDistributionError;
use oci_client::manifest::OciImageManifest;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};

use crate::error::LauncherError;
use crate::types::LauncherConfig;

/// Creates an OCI registry client configured for the launcher's use case.
pub fn create_registry_client(request_timeout: Duration) -> Client {
    let config = ClientConfig {
        protocol: ClientProtocol::Https,
        platform_resolver: Some(Box::new(oci_client::client::linux_amd64_resolver)),
        read_timeout: Some(request_timeout),
        connect_timeout: Some(request_timeout),
        ..Default::default()
    };
    Client::new(config)
}

/// Resolves the manifest digest for an image that matches the expected config digest.
///
/// Iterates over all configured image tags and returns the manifest digest of
/// the first tag whose config digest matches `expected_image_digest`.
/// Multi-platform image indices are resolved to `amd64/linux` automatically.
pub async fn get_manifest_digest(
    client: &Client,
    config: &LauncherConfig,
    expected_image_digest: &DockerSha256Digest,
) -> Result<DockerSha256Digest, LauncherError> {
    let auth = RegistryAuth::Anonymous;

    for tag in config.image_tags.iter() {
        let reference: Reference = format!("{}/{}:{}", config.registry, config.image_name, tag)
            .parse()
            .map_err(|e: oci_client::ParseError| {
                LauncherError::InvalidImageReference(e.to_string())
            })?;

        let backoff = ExponentialBuilder::default()
            .with_min_delay(Duration::from_secs(config.rpc_request_interval_secs))
            .with_factor(1.5)
            .with_max_delay(Duration::from_secs(60))
            .with_max_times(config.rpc_max_attempts as usize);

        let pull_future = || {
            let auth = &auth;
            let reference = &reference;
            async move { client.pull_image_manifest(reference, auth).await }
        };

        let result = pull_future
            .retry(backoff)
            .when(|err: &OciDistributionError| is_retryable(err))
            .notify(|err, dur| {
                tracing::warn!(
                    %reference,
                    ?dur,
                    ?err,
                    "failed to fetch manifest, retrying"
                );
            })
            .await;

        let (manifest, manifest_digest) = match result {
            Ok(value) => value,
            Err(err) => {
                let launcher_err = LauncherError::from(err);
                tracing::warn!(
                    %reference,
                    error = %launcher_err,
                    "failed to fetch manifest. \
                    Will continue in the hopes of finding the matching image hash among remaining tags"
                );
                continue;
            }
        };

        match check_config_digest(&manifest, expected_image_digest) {
            Ok(()) => {
                let digest = parse_manifest_digest(&manifest_digest)?;
                tracing::info!(
                    ?tag,
                    %manifest_digest,
                    "config digest matched, resolved manifest digest"
                );
                return Ok(digest);
            }
            Err(LauncherError::ConfigDigestMismatch { expected, actual }) => {
                tracing::warn!(
                    ?tag,
                    actual_config_digest = %actual,
                    expected_config_digest = %expected,
                    "config digest mismatch, skipping tag"
                );
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    tracing::error!(
        ?expected_image_digest,
        tags = ?config.image_tags,
        "no tag produced a manifest with matching config digest"
    );
    Err(LauncherError::ImageHashNotFoundAmongTags)
}

/// Checks whether a manifest's config digest matches the expected image digest.
///
/// Returns `Ok(())` if the config digest matches, or
/// `Err(ConfigDigestMismatch)` / `Err(RegistryResponseParse)` otherwise.
fn check_config_digest(
    manifest: &OciImageManifest,
    expected_image_digest: &DockerSha256Digest,
) -> Result<(), LauncherError> {
    let config_digest: DockerSha256Digest = manifest.config.digest.parse().map_err(|_| {
        LauncherError::RegistryResponseParse(format!(
            "invalid config digest: {}",
            manifest.config.digest
        ))
    })?;

    if config_digest != *expected_image_digest {
        return Err(LauncherError::ConfigDigestMismatch {
            expected: expected_image_digest.clone(),
            actual: config_digest,
        });
    }

    Ok(())
}

fn parse_manifest_digest(digest: &str) -> Result<DockerSha256Digest, LauncherError> {
    digest.parse().map_err(|_| {
        LauncherError::RegistryResponseParse(format!("failed to parse manifest digest: {digest}"))
    })
}

fn is_retryable(err: &OciDistributionError) -> bool {
    matches!(
        err,
        OciDistributionError::ServerError { .. } | OciDistributionError::RequestError(_)
    )
}

impl From<OciDistributionError> for LauncherError {
    fn from(err: OciDistributionError) -> Self {
        match err {
            OciDistributionError::AuthenticationFailure(msg) => {
                LauncherError::RegistryAuthFailed(msg)
            }
            OciDistributionError::UnauthorizedError { url } => {
                LauncherError::RegistryAuthFailed(format!("unauthorized: {url}"))
            }
            OciDistributionError::ImageManifestNotFoundError(msg) => {
                LauncherError::ManifestNotFound(msg)
            }
            OciDistributionError::ServerError {
                code, url, message, ..
            } => LauncherError::RegistryServerError(format!("{code} {url}: {message}")),
            OciDistributionError::RequestError(err) => {
                LauncherError::RegistryRequestFailed(err.to_string())
            }
            other => LauncherError::RegistryError(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use launcher_interface::types::DockerSha256Digest;
    use oci_client::manifest::{OciDescriptor, OciImageManifest};

    use super::*;

    fn digest(hex_char: char) -> DockerSha256Digest {
        format!(
            "sha256:{}",
            std::iter::repeat_n(hex_char, 64).collect::<String>()
        )
        .parse()
        .unwrap()
    }

    fn manifest_with_config_digest(config_digest: &DockerSha256Digest) -> OciImageManifest {
        OciImageManifest {
            config: OciDescriptor {
                digest: config_digest.to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn check_config_digest_succeeds_on_match() {
        // given
        let expected = digest('a');
        let manifest = manifest_with_config_digest(&expected);

        // when
        let result = check_config_digest(&manifest, &expected);

        // then
        assert_matches!(result, Ok(()));
    }

    #[test]
    fn check_config_digest_errors_on_mismatch() {
        // given
        let expected = digest('a');
        let actual = digest('f');
        let manifest = manifest_with_config_digest(&actual);

        // when
        let result = check_config_digest(&manifest, &expected);

        // then
        assert_matches!(result, Err(LauncherError::ConfigDigestMismatch { expected: e, actual: a }) => {
            assert_eq!(e, expected);
            assert_eq!(a, actual);
        });
    }

    #[test]
    fn check_config_digest_errors_on_invalid_config_digest() {
        // given
        let expected = digest('a');
        let manifest = OciImageManifest {
            config: OciDescriptor {
                digest: "not-a-valid-digest".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };

        // when
        let result = check_config_digest(&manifest, &expected);

        // then
        assert_matches!(result, Err(LauncherError::RegistryResponseParse(msg)) => {
            assert!(msg.contains("invalid config digest"), "unexpected message: {msg}");
        });
    }

    #[test]
    fn parse_manifest_digest_succeeds_for_valid_sha256() {
        let input = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let result = parse_manifest_digest(input);
        assert_matches!(result, Ok(d) => {
            assert_eq!(d.to_string(), input);
        });
    }

    #[test]
    fn parse_manifest_digest_rejects_missing_prefix() {
        let result = parse_manifest_digest(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert_matches!(result, Err(LauncherError::RegistryResponseParse(msg)) => {
            assert!(msg.contains("failed to parse manifest digest"), "unexpected message: {msg}");
        });
    }

    #[test]
    fn parse_manifest_digest_rejects_invalid_format() {
        let result = parse_manifest_digest("not-a-valid-digest");
        assert_matches!(result, Err(LauncherError::RegistryResponseParse(msg)) => {
            assert!(msg.contains("failed to parse manifest digest"), "unexpected message: {msg}");
        });
    }

    #[rstest::rstest]
    #[case::server_error(
        OciDistributionError::ServerError { code: 500, url: "https://example.com".into(), message: "internal".into() },
        true
    )]
    #[case::auth_failure(OciDistributionError::AuthenticationFailure("bad creds".into()), false)]
    #[case::unauthorized(OciDistributionError::UnauthorizedError { url: "https://example.com".into() }, false)]
    #[case::manifest_not_found(OciDistributionError::ImageManifestNotFoundError("missing".into()), false)]
    #[case::generic(OciDistributionError::GenericError(Some("something".into())), false)]
    fn is_retryable_cases(#[case] err: OciDistributionError, #[case] expected: bool) {
        assert_eq!(is_retryable(&err), expected);
    }

    #[rstest::rstest]
    #[case::auth_failure(
        OciDistributionError::AuthenticationFailure("token expired".into()),
        "RegistryAuthFailed"
    )]
    #[case::unauthorized(
        OciDistributionError::UnauthorizedError { url: "https://registry.example.com/v2/".into() },
        "RegistryAuthFailed"
    )]
    #[case::manifest_not_found(
        OciDistributionError::ImageManifestNotFoundError("no such tag".into()),
        "ManifestNotFound"
    )]
    #[case::server_error(
        OciDistributionError::ServerError { code: 503, url: "https://registry.example.com".into(), message: "unavailable".into() },
        "RegistryServerError"
    )]
    #[case::generic_fallback(
        OciDistributionError::GenericError(Some("something weird".into())),
        "RegistryError"
    )]
    fn oci_error_mapping(#[case] err: OciDistributionError, #[case] expected_variant: &str) {
        let result = LauncherError::from(err);
        let debug = format!("{result:?}");
        assert!(
            debug.starts_with(expected_variant),
            "expected {expected_variant}, got: {debug}"
        );
    }
}

/// Tests requiring network access and external registries.
///
/// Run with: `cargo nextest run --cargo-profile=test-release -p tee-launcher --features external-services-tests`
#[cfg(all(test, feature = "external-services-tests"))]
mod integration_tests {
    use launcher_interface::types::DockerSha256Digest;

    #[cfg(target_os = "linux")]
    use {crate::validation::validate_image_hash, assert_matches::assert_matches};

    use super::*;

    const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

    const NEARONE_TESTING_DIGEST: &str =
        "sha256:f2472280c437efc00fa25a030a24990ae16c4fbec0d74914e178473ce4d57372";
    const NEARONE_TESTING_TAG: &str = "83b52da4e2270c688cdd30da04f6b9d3565f25bb";

    /// alpine:3.21.3 amd64/linux config digest (shared across Docker Hub, ECR Public, GCR mirror).
    const ALPINE_CONFIG_DIGEST: &str =
        "sha256:aded1e1a5b3705116fa0a92ba074a5e0b0031647d9c315983ccba2ee5428ec8b";
    const ALPINE_TAG: &str = "3.21.3";

    /// ghcr.io/linuxserver/baseimage-alpine:3.21 amd64/linux config digest.
    const GHCR_ALPINE_CONFIG_DIGEST: &str =
        "sha256:9412ced37d82f91223266bcc1e0a9e05ce7f7d06d4f4fd41e86149be2a37d091";
    const GHCR_ALPINE_TAG: &str = "3.21";

    fn launcher_config(registry: &str, image_name: &str, tag: &str) -> LauncherConfig {
        LauncherConfig {
            image_tags: near_mpc_bounded_collections::NonEmptyVec::from_vec(vec![tag.into()])
                .unwrap(),
            image_name: image_name.into(),
            registry: registry.into(),
            rpc_request_timeout_secs: 30,
            rpc_request_interval_secs: 1,
            rpc_max_attempts: 3,
            mpc_hash_override: None,
            port_mappings: vec![],
        }
    }

    #[rstest::rstest]
    #[case::docker_hub_nearone(
        "registry.hub.docker.com",
        "nearone/testing",
        NEARONE_TESTING_TAG,
        NEARONE_TESTING_DIGEST
    )]
    #[case::docker_hub_alpine(
        "registry.hub.docker.com",
        "library/alpine",
        ALPINE_TAG,
        ALPINE_CONFIG_DIGEST
    )]
    #[case::ghcr(
        "ghcr.io",
        "linuxserver/baseimage-alpine",
        GHCR_ALPINE_TAG,
        GHCR_ALPINE_CONFIG_DIGEST
    )]
    #[case::ecr_public(
        "public.ecr.aws",
        "docker/library/alpine",
        ALPINE_TAG,
        ALPINE_CONFIG_DIGEST
    )]
    #[case::gcr_mirror("mirror.gcr.io", "library/alpine", ALPINE_TAG, ALPINE_CONFIG_DIGEST)]
    #[tokio::test]
    async fn resolves_manifest_digest(
        #[case] registry: &str,
        #[case] image_name: &str,
        #[case] tag: &str,
        #[case] config_digest: &str,
    ) {
        // given
        let config = launcher_config(registry, image_name, tag);
        let expected: DockerSha256Digest = config_digest.parse().unwrap();
        let client = create_registry_client(REQUEST_TIMEOUT);

        // when
        let result = get_manifest_digest(&client, &config, &expected).await;

        // then
        assert!(result.is_ok(), "{registry} failed: {result:?}");
    }

    // `validate_image_hash` compares the output of `docker inspect .ID` against
    // the expected config digest. On native Linux, `.ID` returns the config digest
    // (sha256 of the image config blob), but on macOS, Docker Desktop's containerd
    // image store returns the manifest digest instead, causing a spurious mismatch.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn validate_image_hash_succeeds_for_known_image() {
        // given
        let config = launcher_config(
            "registry.hub.docker.com",
            "nearone/testing",
            NEARONE_TESTING_TAG,
        );
        let expected: DockerSha256Digest = NEARONE_TESTING_DIGEST.parse().unwrap();

        // when
        let result = validate_image_hash(&config, expected).await;

        // then
        assert_matches!(result, Ok(_));
    }
}
