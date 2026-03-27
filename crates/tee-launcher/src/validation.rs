use std::process::Command;

use launcher_interface::types::DockerSha256Digest;

use crate::error::ImageDigestValidationFailed;
use crate::registry::{DockerRegistry, get_manifest_digest};
use crate::types::LauncherConfig;

/// Returns if the given image digest is valid (pull + manifest + digest match).
/// Does NOT extend RTMR3 and does NOT run the container.
pub async fn validate_image_hash(
    launcher_config: &LauncherConfig,
    image_hash: DockerSha256Digest,
) -> Result<DockerSha256Digest, ImageDigestValidationFailed> {
    let registry = DockerRegistry::new(launcher_config);
    let manifest_digest = get_manifest_digest(&registry, launcher_config, &image_hash)
        .await
        .map_err(|e| ImageDigestValidationFailed::ManifestDigestLookupFailed(e.to_string()))?;
    let image_name = &launcher_config.image_name;

    let name_and_digest = format!("{image_name}@{manifest_digest}");

    // Pull
    let pull = Command::new("docker")
        .args(["pull", &name_and_digest])
        .output()
        .map_err(|e| ImageDigestValidationFailed::DockerPullFailed(e.to_string()))?;

    let pull_failed = !pull.status.success();
    if pull_failed {
        return Err(ImageDigestValidationFailed::DockerPullFailed(
            "docker pull terminated with unsuccessful status".to_string(),
        ));
    }

    // Verify that the pulled image ID matches the expected config digest.
    // `docker inspect .ID` returns the image ID, which equals the config digest
    // (i.e. the sha256 of the image config blob).
    let inspect = Command::new("docker")
        .args([
            "image",
            "inspect",
            "--format",
            "{{index .ID}}",
            &name_and_digest,
        ])
        .output()
        .map_err(|e| ImageDigestValidationFailed::DockerInspectFailed(e.to_string()))?;

    let docker_inspect_failed = !inspect.status.success();
    if docker_inspect_failed {
        return Err(ImageDigestValidationFailed::DockerInspectFailed(
            "docker inspect terminated with unsuccessful status".to_string(),
        ));
    }

    let pulled_image_id: DockerSha256Digest = String::from_utf8_lossy(&inspect.stdout)
        .trim()
        .to_string()
        .parse()
        .map_err(|e| {
            ImageDigestValidationFailed::DockerInspectFailed(format!(
                "docker inspect returned invalid image ID: {e}"
            ))
        })?;

    if pulled_image_id != image_hash {
        return Err(
            ImageDigestValidationFailed::PulledImageHasMismatchedDigest {
                pulled_image_id,
                expected_image_id: image_hash,
            },
        );
    }

    Ok(manifest_digest)
}
