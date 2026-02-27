use std::collections::VecDeque;
use std::process::Command;
use std::time::Duration;

use crate::config::{ResolvedImage, RpcTimingConfig};

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("no tags provided for image {0}")]
    NoTags(String),
    #[error("failed to get Docker Hub auth token: {0}")]
    AuthFailed(String),
    #[error("image hash not found among tags after exhausting all attempts")]
    HashNotFound,
    #[error("docker pull failed for {image}: {stderr}")]
    PullFailed { image: String, stderr: String },
    #[error("docker inspect failed for {image}: {stderr}")]
    InspectFailed { image: String, stderr: String },
    #[error("digest mismatch: pulled {pulled}, expected {expected}")]
    DigestMismatch { pulled: String, expected: String },
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("max attempts ({max}) exceeded for {url}")]
    MaxAttemptsExceeded { url: String, max: u32 },
    #[error("missing Docker-Content-Digest header")]
    MissingContentDigest,
}

/// Obtain an auth token from Docker Hub for the given image name.
fn get_docker_auth_token(
    client: &reqwest::blocking::Client,
    image_name: &str,
) -> Result<String, RegistryError> {
    let url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image_name}:pull"
    );
    let resp = client.get(&url).send()?.error_for_status()?;
    let body: serde_json::Value = resp.json()?;
    body.get("token")
        .and_then(|t| t.as_str())
        .map(String::from)
        .ok_or_else(|| RegistryError::AuthFailed("missing token in response".to_string()))
}

/// Fetch a URL with retries and exponential backoff.
/// Returns the response on 200, or errors after max_attempts.
fn request_until_success(
    client: &reqwest::blocking::Client,
    url: &str,
    token: &str,
    timing: &RpcTimingConfig,
) -> Result<reqwest::blocking::Response, RegistryError> {
    let mut interval = timing.interval_secs;

    for attempt in 1..=timing.max_attempts {
        std::thread::sleep(Duration::from_secs_f64(interval));
        interval = (interval.max(1.0) * 1.5).min(60.0);

        let result = client
            .get(url)
            .header(
                "Accept",
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .header("Authorization", format!("Bearer {token}"))
            .timeout(Duration::from_secs_f64(timing.timeout_secs))
            .send();

        match result {
            Ok(resp) if resp.status().is_success() => return Ok(resp),
            Ok(resp) => {
                tracing::warn!(
                    "Attempt {attempt}/{}: Failed to fetch {url}. Status: {}",
                    timing.max_attempts,
                    resp.status()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Attempt {attempt}/{}: Failed to fetch {url}. Error: {e}",
                    timing.max_attempts
                );
            }
        }
    }

    Err(RegistryError::MaxAttemptsExceeded {
        url: url.to_string(),
        max: timing.max_attempts,
    })
}

/// Given a resolved image, iterate through tags and multi-platform manifests
/// to find the manifest digest whose config digest matches the expected image digest.
/// Returns the manifest digest (Docker-Content-Digest header value).
pub fn get_manifest_digest(
    client: &reqwest::blocking::Client,
    image: &ResolvedImage,
    timing: &RpcTimingConfig,
) -> Result<String, RegistryError> {
    if image.spec.tags.is_empty() {
        return Err(RegistryError::NoTags(image.spec.image_name.clone()));
    }

    let token = get_docker_auth_token(client, &image.spec.image_name)?;

    let mut tags: VecDeque<String> = image.spec.tags.iter().cloned().collect();

    while let Some(tag) = tags.pop_front() {
        let manifest_url = format!(
            "https://{}/v2/{}/manifests/{tag}",
            image.spec.registry, image.spec.image_name
        );

        let resp = match request_until_success(client, &manifest_url, &token, timing) {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(
                    "{e}: Exceeded max RPC requests for tag {tag}. \
                     Continuing with remaining tags."
                );
                continue;
            }
        };

        // Extract Docker-Content-Digest header BEFORE consuming body
        let content_digest = resp
            .headers()
            .get("Docker-Content-Digest")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let manifest: serde_json::Value = match resp.json() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("Failed to parse manifest for tag {tag}: {e}");
                continue;
            }
        };

        let media_type = manifest
            .get("mediaType")
            .and_then(|m| m.as_str())
            .unwrap_or("");

        match media_type {
            // Multi-platform manifest: scan for amd64/linux images
            "application/vnd.oci.image.index.v1+json" => {
                if let Some(manifests) = manifest.get("manifests").and_then(|m| m.as_array()) {
                    for img_manifest in manifests {
                        let platform = img_manifest.get("platform");
                        let arch = platform
                            .and_then(|p| p.get("architecture"))
                            .and_then(|a| a.as_str());
                        let os = platform.and_then(|p| p.get("os")).and_then(|o| o.as_str());
                        if arch == Some("amd64") && os == Some("linux") {
                            if let Some(digest) =
                                img_manifest.get("digest").and_then(|d| d.as_str())
                            {
                                tags.push_back(digest.to_string());
                            }
                        }
                    }
                }
            }
            // Single-platform manifest
            "application/vnd.docker.distribution.manifest.v2+json"
            | "application/vnd.oci.image.manifest.v1+json" => {
                let config_digest = manifest
                    .get("config")
                    .and_then(|c| c.get("digest"))
                    .and_then(|d| d.as_str());

                if config_digest == Some(image.digest.full()) {
                    return content_digest.ok_or(RegistryError::MissingContentDigest);
                }
            }
            _ => {
                tracing::warn!("Unknown manifest mediaType: {media_type}");
            }
        }
    }

    Err(RegistryError::HashNotFound)
}

/// Full validation: resolve manifest, docker pull by manifest digest, docker inspect to verify.
/// Returns the manifest digest on success.
pub fn validate_image_hash(
    image: &ResolvedImage,
    timing: &RpcTimingConfig,
) -> Result<String, RegistryError> {
    tracing::info!("Validating MPC hash: {}", image.digest.full());

    let client = reqwest::blocking::Client::new();
    let manifest_digest = get_manifest_digest(&client, image, timing)?;

    let name_and_digest = format!("{}@{manifest_digest}", image.spec.image_name);

    // Pull
    let pull_output = Command::new("docker")
        .args(["pull", &name_and_digest])
        .output()
        .map_err(|e| RegistryError::PullFailed {
            image: name_and_digest.clone(),
            stderr: e.to_string(),
        })?;

    if !pull_output.status.success() {
        return Err(RegistryError::PullFailed {
            image: name_and_digest,
            stderr: String::from_utf8_lossy(&pull_output.stderr).to_string(),
        });
    }

    // Verify digest
    let inspect_output = Command::new("docker")
        .args([
            "image",
            "inspect",
            "--format",
            "{{index .ID}}",
            &name_and_digest,
        ])
        .output()
        .map_err(|e| RegistryError::InspectFailed {
            image: name_and_digest.clone(),
            stderr: e.to_string(),
        })?;

    if !inspect_output.status.success() {
        return Err(RegistryError::InspectFailed {
            image: name_and_digest,
            stderr: String::from_utf8_lossy(&inspect_output.stderr).to_string(),
        });
    }

    let pulled_digest = String::from_utf8_lossy(&inspect_output.stdout)
        .trim()
        .to_string();

    if pulled_digest != image.digest.full() {
        return Err(RegistryError::DigestMismatch {
            pulled: pulled_digest,
            expected: image.digest.full().to_string(),
        });
    }

    tracing::info!("MPC hash {} validated successfully", image.digest.full());
    Ok(manifest_digest)
}
