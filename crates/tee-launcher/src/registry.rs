use std::collections::VecDeque;
use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};
use launcher_interface::types::DockerSha256Digest;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue};
use url::Url;

use crate::docker_types::{DockerTokenResponse, ManifestResponse};
use crate::error::LauncherError;
use crate::types::LauncherConfig;

const DOCKER_AUTH_ACCEPT_HEADER_VALUE: HeaderValue =
    HeaderValue::from_static("application/vnd.docker.distribution.manifest.v2+json");

const DOCKER_CONTENT_DIGEST_HEADER: &str = "Docker-Content-Digest";
// TODO(#2479): if we use a different registry, we need a different auth-endpoint
const DOCKER_AUTH_TOKEN_URL: &str =
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:";

const AMD64: &str = "amd64";
const LINUX: &str = "linux";

/// Provides the URLs needed to interact with a container registry.
pub(crate) trait RegistryInfo {
    fn token_url(&self) -> String;
    fn manifest_url(&self, tag: &str) -> Result<Url, LauncherError>;
}

/// Production registry info for Docker Hub.
pub(crate) struct DockerRegistry {
    registry_base_url: String,
    image_name: String,
}

impl DockerRegistry {
    pub(crate) fn new(config: &LauncherConfig) -> Self {
        Self {
            registry_base_url: format!("https://{}", config.registry),
            image_name: config.image_name.clone(),
        }
    }
}

impl RegistryInfo for DockerRegistry {
    fn token_url(&self) -> String {
        format!("{}{}:pull", DOCKER_AUTH_TOKEN_URL, self.image_name)
    }

    fn manifest_url(&self, tag: &str) -> Result<Url, LauncherError> {
        let url_string = format!(
            "{}/v2/{}/manifests/{tag}",
            self.registry_base_url, self.image_name
        );

        url_string
            .parse()
            .map_err(|_| LauncherError::InvalidManifestUrl(url_string))
    }
}

pub(crate) async fn get_manifest_digest(
    registry: &impl RegistryInfo,
    config: &LauncherConfig,
    expected_image_digest: &DockerSha256Digest,
) -> Result<DockerSha256Digest, LauncherError> {
    let mut tags: VecDeque<String> = config.image_tags.iter().cloned().collect();

    let reqwest_client = reqwest::Client::new();

    // We need an authorization token to fetch manifests.
    let token_url = registry.token_url();

    let token_request_response = reqwest_client
        .get(token_url)
        .timeout(Duration::from_secs(config.rpc_request_timeout_secs))
        .send()
        .await
        .map_err(|e| LauncherError::RegistryAuthFailed(e.to_string()))?;

    let status = token_request_response.status();
    if !status.is_success() {
        return Err(LauncherError::RegistryAuthFailed(format!(
            "token request returned non-success status: {status}"
        )));
    }

    let token_response: DockerTokenResponse = token_request_response
        .json()
        .await
        .map_err(|e| LauncherError::RegistryAuthFailed(e.to_string()))?;

    while let Some(tag) = tags.pop_front() {
        let manifest_url = registry.manifest_url(&tag)?;

        let authorization_value: HeaderValue = format!("Bearer {}", token_response.token)
            .parse()
            .expect("bearer token received from docker auth is a valid header value");

        let headers = HeaderMap::from_iter([
            (ACCEPT, DOCKER_AUTH_ACCEPT_HEADER_VALUE),
            (AUTHORIZATION, authorization_value),
        ]);

        let request_timeout = Duration::from_secs(config.rpc_request_timeout_secs);
        let backoff = ExponentialBuilder::default()
            .with_min_delay(Duration::from_secs(config.rpc_request_interval_secs))
            .with_factor(1.5)
            .with_max_delay(Duration::from_secs(60))
            .with_max_times(config.rpc_max_attempts as usize);

        let request_future = || async {
            reqwest_client
                .get(manifest_url.clone())
                .headers(headers.clone())
                .timeout(request_timeout)
                .send()
                .await?
                .error_for_status()
        };

        let request_with_retry_future = request_future
            .retry(backoff)
            .when(|err: &reqwest::Error| {
                err.is_timeout()
                    || err.is_connect()
                    || err.status().is_some_and(|s| s.is_server_error())
            })
            .notify(|err, dur| {
                tracing::warn!(
                    ?manifest_url,
                    ?dur,
                    ?err,
                    "failed to fetch manifest, retrying"
                );
            });

        let Ok(resp) = request_with_retry_future.await else {
            tracing::warn!(
                ?manifest_url,
                "exceeded max RPC attempts. \
                Will continue in the hopes of finding the matching image hash among remaining tags"
            );
            continue;
        };

        let response_headers = resp.headers().clone();
        let manifest: ManifestResponse = resp
            .json()
            .await
            .map_err(|e| LauncherError::RegistryResponseParse(e.to_string()))?;

        match manifest {
            ManifestResponse::ImageIndex { manifests } => {
                let platform_digests: Vec<_> = manifests
                    .iter()
                    .filter(|m| m.platform.architecture == AMD64 && m.platform.os == LINUX)
                    .map(|m| m.digest.as_str())
                    .collect();
                tracing::info!(
                    ?tag,
                    ?platform_digests,
                    "received multi-platform image index, queuing amd64/linux manifests"
                );
                manifests
                    .into_iter()
                    .filter(|manifest| {
                        manifest.platform.architecture == AMD64 && manifest.platform.os == LINUX
                    })
                    .for_each(|manifest| tags.push_back(manifest.digest));
            }
            ManifestResponse::DockerV2 { config } | ManifestResponse::OciManifest { config } => {
                if config.digest != *expected_image_digest {
                    tracing::warn!(
                        ?tag,
                        actual_config_digest = %config.digest,
                        expected_config_digest = %expected_image_digest,
                        "config digest mismatch, skipping tag"
                    );
                    continue;
                }

                let Some(content_digest) = response_headers
                    .get(DOCKER_CONTENT_DIGEST_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                else {
                    tracing::warn!(
                        ?tag,
                        "manifest matched but Docker-Content-Digest header missing, skipping"
                    );
                    continue;
                };

                tracing::info!(
                    ?tag,
                    %content_digest,
                    "config digest matched, resolved manifest digest"
                );
                return content_digest.parse().map_err(|_| {
                    LauncherError::RegistryResponseParse(format!(
                        "failed to parse manifest digest: {}",
                        content_digest
                    ))
                });
            }
        }
    }

    tracing::error!(
        ?expected_image_digest,
        tags = ?config.image_tags,
        "no tag produced a manifest with matching config digest"
    );
    Err(LauncherError::ImageHashNotFoundAmongTags)
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use httpmock::prelude::*;
    use launcher_interface::types::DockerSha256Digest;

    use super::*;

    fn digest(hex_char: char) -> DockerSha256Digest {
        format!(
            "sha256:{}",
            std::iter::repeat_n(hex_char, 64).collect::<String>()
        )
        .parse()
        .unwrap()
    }

    fn sample_digest() -> DockerSha256Digest {
        digest('a')
    }

    struct MockRegistry {
        base_url: String,
        image_name: String,
    }

    impl RegistryInfo for MockRegistry {
        fn token_url(&self) -> String {
            format!("{}/token", self.base_url)
        }

        fn manifest_url(&self, tag: &str) -> Result<Url, LauncherError> {
            let raw = format!("{}/v2/{}/manifests/{tag}", self.base_url, self.image_name);
            raw.parse()
                .map_err(|_| LauncherError::InvalidManifestUrl(raw))
        }
    }

    fn mock_launcher_config(tag: &str) -> LauncherConfig {
        LauncherConfig {
            image_tags: near_mpc_bounded_collections::NonEmptyVec::from_vec(vec![tag.into()])
                .unwrap(),
            image_name: "test/image".into(),
            registry: "unused".into(),
            rpc_request_timeout_secs: 5,
            rpc_request_interval_secs: 1,
            rpc_max_attempts: 1,
            mpc_hash_override: None,
            port_mappings: vec![],
        }
    }

    fn mock_registry(server: &MockServer) -> MockRegistry {
        MockRegistry {
            base_url: server.base_url(),
            image_name: "test/image".into(),
        }
    }

    #[tokio::test]
    async fn get_manifest_digest_resolves_docker_v2() {
        // given
        let server = MockServer::start();
        let expected_image_digest = sample_digest();
        let manifest_digest = digest('b');

        server.mock(|when, then| {
            when.method(GET).path("/token");
            then.status(200)
                .json_body(serde_json::json!({ "token": "test-token" }));
        });

        let manifest_body = serde_json::json!({
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": { "digest": expected_image_digest.to_string() }
        });

        server.mock(|when, then| {
            when.method(GET).path("/v2/test/image/manifests/v1.0");
            then.status(200)
                .header("Docker-Content-Digest", manifest_digest.to_string())
                .json_body(manifest_body);
        });

        let registry = mock_registry(&server);
        let config = mock_launcher_config("v1.0");

        // when
        let result = get_manifest_digest(&registry, &config, &expected_image_digest).await;

        // then
        assert_matches!(result, Ok(d) => {
            assert_eq!(d, manifest_digest);
        });
    }

    #[tokio::test]
    async fn get_manifest_digest_follows_image_index_to_amd64_manifest() {
        // given
        let server = MockServer::start();
        let expected_image_digest = sample_digest();
        let manifest_digest = digest('c');
        let amd64_ref = "sha256:amd64ref";

        server.mock(|when, then| {
            when.method(GET).path("/token");
            then.status(200)
                .json_body(serde_json::json!({ "token": "test-token" }));
        });

        // First request: image index pointing to amd64 manifest
        server.mock(|when, then| {
            when.method(GET).path("/v2/test/image/manifests/latest");
            then.status(200).json_body(serde_json::json!({
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "digest": amd64_ref,
                        "platform": { "architecture": "amd64", "os": "linux" }
                    },
                    {
                        "digest": "sha256:armref",
                        "platform": { "architecture": "arm64", "os": "linux" }
                    }
                ]
            }));
        });

        // Second request: the resolved amd64 manifest
        server.mock(|when, then| {
            when.method(GET)
                .path(format!("/v2/test/image/manifests/{amd64_ref}"));
            then.status(200)
                .header("Docker-Content-Digest", manifest_digest.to_string())
                .json_body(serde_json::json!({
                    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                    "config": { "digest": expected_image_digest.to_string() }
                }));
        });

        let registry = mock_registry(&server);
        let config = mock_launcher_config("latest");

        // when
        let result = get_manifest_digest(&registry, &config, &expected_image_digest).await;

        // then
        assert_matches!(result, Ok(d) => {
            assert_eq!(d, manifest_digest);
        });
    }

    #[tokio::test]
    async fn get_manifest_digest_skips_mismatched_config_digest() {
        // given
        let server = MockServer::start();
        let expected_image_digest = sample_digest();
        let wrong_digest = digest('f');

        server.mock(|when, then| {
            when.method(GET).path("/token");
            then.status(200)
                .json_body(serde_json::json!({ "token": "test-token" }));
        });

        server.mock(|when, then| {
            when.method(GET).path("/v2/test/image/manifests/v1.0");
            then.status(200)
                .header("Docker-Content-Digest", "sha256:doesntmatter")
                .json_body(serde_json::json!({
                    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                    "config": { "digest": wrong_digest.to_string() }
                }));
        });

        let registry = mock_registry(&server);
        let config = mock_launcher_config("v1.0");

        // when
        let result = get_manifest_digest(&registry, &config, &expected_image_digest).await;

        // then
        assert_matches!(result, Err(LauncherError::ImageHashNotFoundAmongTags));
    }

    #[tokio::test]
    async fn get_manifest_digest_errors_on_auth_failure() {
        // given
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(GET).path("/token");
            then.status(403);
        });

        let registry = mock_registry(&server);
        let config = mock_launcher_config("v1.0");

        // when
        let result = get_manifest_digest(&registry, &config, &sample_digest()).await;

        // then
        assert_matches!(result, Err(LauncherError::RegistryAuthFailed(_)));
    }

    #[tokio::test]
    async fn get_manifest_digest_missing_content_digest_header_skips_tag() {
        // given
        let server = MockServer::start();
        let expected_image_digest = sample_digest();

        server.mock(|when, then| {
            when.method(GET).path("/token");
            then.status(200)
                .json_body(serde_json::json!({ "token": "test-token" }));
        });

        // Manifest matches but no Docker-Content-Digest header
        server.mock(|when, then| {
            when.method(GET).path("/v2/test/image/manifests/v1.0");
            then.status(200).json_body(serde_json::json!({
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "config": { "digest": expected_image_digest.to_string() }
            }));
        });

        let registry = mock_registry(&server);
        let config = mock_launcher_config("v1.0");

        // when
        let result = get_manifest_digest(&registry, &config, &expected_image_digest).await;

        // then - tag is skipped, no more tags → error
        assert_matches!(result, Err(LauncherError::ImageHashNotFoundAmongTags));
    }
}

/// Tests requiring network access and Docker Hub.
#[cfg(all(test, feature = "external-services-tests"))]
mod integration_tests {
    use assert_matches::assert_matches;
    use launcher_interface::types::DockerSha256Digest;

    use super::*;
    use crate::validation::validate_image_hash;

    //     # Dockerfile
    // FROM alpine@sha256:765942a4039992336de8dd5db680586e1a206607dd06170ff0a37267a9e01958
    // CMD ["true"]
    // TODO: Look into reusing this image, as its small and will be faster on  CI

    const TEST_DIGEST: &str =
        "sha256:f2472280c437efc00fa25a030a24990ae16c4fbec0d74914e178473ce4d57372";
    const TEST_TAG: &str = "83b52da4e2270c688cdd30da04f6b9d3565f25bb";
    const TEST_IMAGE_NAME: &str = "nearone/testing";
    const TEST_REGISTRY: &str = "registry.hub.docker.com";

    fn test_launcher_config() -> LauncherConfig {
        LauncherConfig {
            image_tags: near_mpc_bounded_collections::NonEmptyVec::from_vec(vec![TEST_TAG.into()])
                .unwrap(),
            image_name: TEST_IMAGE_NAME.into(),
            registry: TEST_REGISTRY.into(),
            rpc_request_timeout_secs: 10,
            rpc_request_interval_secs: 1,
            rpc_max_attempts: 20,
            mpc_hash_override: None,
            port_mappings: vec![],
        }
    }

    #[tokio::test]
    async fn get_manifest_digest_resolves_known_image() {
        // given
        let config = test_launcher_config();
        let expected_digest: DockerSha256Digest = TEST_DIGEST.parse().unwrap();

        // when
        let registry = DockerRegistry::new(&config);
        let result = get_manifest_digest(&registry, &config, &expected_digest).await;

        // then
        assert!(result.is_ok(), "get_manifest_digest failed: {result:?}");
    }

    // `validate_image_hash` compares the output of `docker inspect .ID` against
    // the expected config digest. On native Linux, `.ID` returns the config digest
    // (sha256 of the image config blob), but on macOS, Docker Desktop's containerd
    // image store returns the manifest digest instead, causing a spurious mismatch.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn validate_image_hash_succeeds_for_known_image() {
        // given
        let config = test_launcher_config();
        let expected_digest: DockerSha256Digest = TEST_DIGEST.parse().unwrap();

        // when
        let result = validate_image_hash(&config, expected_digest).await;

        // then
        assert_matches!(result, Ok(_));
    }
}
