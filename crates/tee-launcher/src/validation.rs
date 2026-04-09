use std::process::Command;

use launcher_interface::types::DockerSha256Digest;

use crate::error::ImageDigestValidationFailed;

/// Pulls the image by manifest digest and verifies the pull succeeded.
///
/// The approved hashes file contains manifest digests, so we can pull directly
/// without querying the Docker registry API.
pub fn pull_and_verify(
    image_name: &str,
    manifest_digest: &DockerSha256Digest,
) -> Result<(), ImageDigestValidationFailed> {
    let reference = format!("{image_name}@{manifest_digest}");

    let pull = Command::new("docker")
        .args(["pull", &reference])
        .output()
        .map_err(|e| ImageDigestValidationFailed::DockerPullFailed(e.to_string()))?;

    if !pull.status.success() {
        let stderr = String::from_utf8_lossy(&pull.stderr);
        return Err(ImageDigestValidationFailed::DockerPullFailed(format!(
            "docker pull {reference} failed: {stderr}"
        )));
    }

    tracing::info!(%reference, "image pulled successfully");
    Ok(())
}
