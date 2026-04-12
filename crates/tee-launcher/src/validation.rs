use std::process::Command;
use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};
use launcher_interface::types::DockerSha256Digest;

use crate::error::ImageDigestValidationFailed;

/// Pulls the image by manifest digest with retry logic.
///
/// The approved hashes file contains manifest digests, so we can pull directly
/// without querying the Docker registry API. Docker verifies the content
/// matches the digest during the pull.
pub async fn pull_and_verify(
    image_name: &str,
    manifest_digest: &DockerSha256Digest,
    max_retries: usize,
    retry_interval_secs: u64,
) -> Result<(), ImageDigestValidationFailed> {
    let reference = format!("{image_name}@{manifest_digest}");

    let pull_fn = || async {
        tracing::info!(%reference, "pulling image");

        let pull = Command::new("docker")
            .args(["pull", &reference])
            .output()
            .map_err(|e| ImageDigestValidationFailed::DockerPullFailed {
                reference: reference.clone(),
                detail: e.to_string(),
            })?;

        if !pull.status.success() {
            let stderr = String::from_utf8_lossy(&pull.stderr).to_string();
            let stdout = String::from_utf8_lossy(&pull.stdout).to_string();
            return Err(ImageDigestValidationFailed::DockerPullFailed {
                reference: reference.clone(),
                detail: format!(
                    "exit code {}: stderr={stderr}, stdout={stdout}",
                    pull.status
                ),
            });
        }

        Ok(())
    };

    let max_delay_secs = 60;
    let backoff = ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(retry_interval_secs.min(max_delay_secs)))
        .with_factor(1.5)
        .with_max_delay(Duration::from_secs(max_delay_secs))
        .with_max_times(max_retries);

    pull_fn
        .retry(backoff)
        .notify(|err, dur| {
            tracing::warn!(
                %reference,
                ?dur,
                ?err,
                "docker pull failed, retrying"
            );
        })
        .await?;

    tracing::info!(%reference, "image pulled successfully");
    Ok(())
}

#[cfg(all(test, feature = "external-services-tests"))]
mod integration_tests {
    use super::*;

    /// Known manifest digest for nearone/testing:83b52da4e2270c688cdd30da04f6b9d3565f25bb
    /// This is a small test image that should always be available.
    const DOCKER_HUB_IMAGE: &str = "nearone/testing";
    const DOCKER_HUB_MANIFEST_DIGEST: &str =
        "sha256:1b155a392e5e84b39ff2ae05a14bcc2764107b53da2e8fceec2e3bd69ed5fe54";

    /// Known manifest digest for ghcr.io/linuxserver/baseimage-alpine:3.21
    const GHCR_IMAGE: &str = "ghcr.io/linuxserver/baseimage-alpine";
    const GHCR_MANIFEST_DIGEST: &str =
        "sha256:eb8b3498f8e0c5191e4d0a1c8b50148d48e33284a498498dff0e9e183206af30";

    #[tokio::test]
    async fn pull_from_docker_hub() {
        let digest: DockerSha256Digest = DOCKER_HUB_MANIFEST_DIGEST.parse().unwrap();
        let result = pull_and_verify(DOCKER_HUB_IMAGE, &digest, 3, 1).await;
        assert!(result.is_ok(), "Docker Hub pull failed: {result:?}");
    }

    #[tokio::test]
    async fn pull_from_ghcr() {
        let digest: DockerSha256Digest = GHCR_MANIFEST_DIGEST.parse().unwrap();
        let result = pull_and_verify(GHCR_IMAGE, &digest, 3, 1).await;
        assert!(result.is_ok(), "GHCR pull failed: {result:?}");
    }

    #[tokio::test]
    async fn pull_with_wrong_digest_fails() {
        let bad_digest: DockerSha256Digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap();
        let result = pull_and_verify(DOCKER_HUB_IMAGE, &bad_digest, 0, 1).await;
        assert!(result.is_err(), "should fail with wrong digest");
    }
}
