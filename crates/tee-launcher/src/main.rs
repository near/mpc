use std::io::Write;
use std::process::Command;
use std::{collections::VecDeque, time::Duration};

use backon::{ExponentialBuilder, Retryable};
use clap::Parser;
use launcher_interface::MPC_IMAGE_HASH_EVENT;
use launcher_interface::types::{ApprovedHashes, DockerSha256Digest};

use constants::*;
use docker_types::*;
use error::*;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue};

use types::*;
use url::Url;

mod constants;
mod docker_types;
mod error;
mod types;

const COMPOSE_TEMPLATE: &str = include_str!("../docker-compose.template.yml");
const COMPOSE_TEE_TEMPLATE: &str = include_str!("../docker-compose.tee.template.yml");

const DOCKER_AUTH_ACCEPT_HEADER_VALUE: HeaderValue =
    HeaderValue::from_static("application/vnd.docker.distribution.manifest.v2+json");

const DOCKER_CONTENT_DIGEST_HEADER: &str = "Docker-Content-Digest";

const AMD64: &str = "amd64";
const LINUX: &str = "linux";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), LauncherError> {
    tracing::info!("start");

    let args = CliArgs::parse();

    tracing::info!(platform = ?args.platform, "starting launcher");

    // Load dstack user config (TOML)
    let config_contents = std::fs::read_to_string(DSTACK_USER_CONFIG_FILE).map_err(|source| {
        LauncherError::FileRead {
            path: DSTACK_USER_CONFIG_FILE.to_string(),
            source,
        }
    })?;

    let dstack_config: Config =
        toml::from_str(&config_contents).map_err(|source| LauncherError::TomlParse {
            path: DSTACK_USER_CONFIG_FILE.to_string(),
            source,
        })?;

    let approved_hashes_file = std::fs::OpenOptions::new()
        .read(true)
        .open(IMAGE_DIGEST_FILE)
        .map_err(|source| LauncherError::FileRead {
            path: IMAGE_DIGEST_FILE.to_string(),
            source,
        });

    let approved_hashes_on_disk: Option<ApprovedHashes> = match approved_hashes_file {
        Err(err) => {
            tracing::warn!(
                ?err,
                default_image_digest = ?args.default_image_digest,
                "approved hashes file does not exist on disk, falling back to default digest"
            );
            None
        }
        Ok(file) => {
            let parsed: ApprovedHashes =
                serde_json::from_reader(file).map_err(|source| LauncherError::JsonParse {
                    path: IMAGE_DIGEST_FILE.to_string(),
                    source,
                })?;
            Some(parsed)
        }
    };

    let image_hash = select_image_hash(
        approved_hashes_on_disk.as_ref(),
        &args.default_image_digest,
        dstack_config.launcher_config.mpc_hash_override.as_ref(),
    )?;

    let () = validate_image_hash(&dstack_config.launcher_config, image_hash.clone()).await?;

    let should_extend_rtmr_3 = args.platform == Platform::Tee;

    if should_extend_rtmr_3 {
        let dstack_client = dstack_sdk::dstack_client::DstackClient::new(Some(DSTACK_UNIX_SOCKET));

        // EmitEvent with the image digest
        dstack_client
            .emit_event(
                MPC_IMAGE_HASH_EVENT.to_string(),
                // TODO: mpc binary has to go back from back hex as well. Just send the raw bytes as payload.
                image_hash.as_raw_hex().as_bytes().to_vec(),
            )
            .await
            .map_err(|e| LauncherError::DstackEmitEventFailed(e.to_string()))?;
    }

    let mpc_binary_config_path = std::path::Path::new("/tmp/mpc-config");
    let mpc_config_toml = toml::to_string(&dstack_config.mpc_config)
        .expect("re-serializing a toml::Table always succeeds");
    std::fs::write(mpc_binary_config_path, mpc_config_toml.as_bytes()).map_err(|source| {
        LauncherError::FileWrite {
            path: mpc_binary_config_path.display().to_string(),
            source,
        }
    })?;

    launch_mpc_container(
        args.platform,
        &image_hash,
        mpc_binary_config_path,
        &dstack_config.docker_command_config,
    )?;

    Ok(())
}

/// Select which image hash to use, given the approved hashes file (if present),
/// a fallback default digest, and an optional user override.
///
/// Selection rules:
///   - If the approved hashes file is absent → use `default_digest`
///   - If `override_hash` is set and appears in the approved list → use it
///   - If `override_hash` is set but NOT in the approved list → error
///   - Otherwise → use the newest approved hash (first in the list)
fn select_image_hash(
    approved_hashes: Option<&ApprovedHashes>,
    default_digest: &DockerSha256Digest,
    override_hash: Option<&DockerSha256Digest>,
) -> Result<DockerSha256Digest, LauncherError> {
    let Some(approved) = approved_hashes else {
        tracing::info!("no approved hashes file, using default digest");
        return Ok(default_digest.clone());
    };

    if let Some(override_image) = override_hash {
        tracing::info!(?override_image, "override mpc image hash provided");
        if !approved.approved_hashes.contains(override_image) {
            return Err(LauncherError::InvalidHashOverride(format!(
                "MPC_HASH_OVERRIDE={override_image} does not match any approved hash",
            )));
        }
        return Ok(override_image.clone());
    }

    let selected = approved.newest_approved_hash().clone();
    tracing::info!(?selected, "selected newest approved hash");
    Ok(selected)
}

async fn get_manifest_digest(
    config: &LauncherConfig,
    expected_image_digest: &DockerSha256Digest,
) -> Result<String, LauncherError> {
    let mut tags: VecDeque<String> = config.image_tags.iter().cloned().collect();

    // We need an authorization token to fetch manifests.
    // TODO: this still has the registry hard-coded in the url. also, if we use a different registry, we need a different auth-endpoint
    let token_url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
        config.image_name
    );

    let reqwest_client = reqwest::Client::new();

    let token_request_response = reqwest_client
        .get(token_url)
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
        let manifest_url: Url = format!(
            "https://{}/v2/{}/manifests/{tag}",
            config.registry, config.image_name
        )
        .parse()
        .map_err(|_| {
            LauncherError::InvalidManifestUrl(format!(
                "https://{}/v2/{}/manifests/{tag}",
                config.registry, config.image_name
            ))
        })?;

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
            .when(|_: &reqwest::Error| true)
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
                // Multi-platform manifest; scan for amd64/linux
                manifests
                    .into_iter()
                    .filter(|manifest| {
                        manifest.platform.architecture == AMD64 && manifest.platform.os == LINUX
                    })
                    .for_each(|manifest| tags.push_back(manifest.digest));
            }
            ManifestResponse::DockerV2 { config } | ManifestResponse::OciManifest { config } => {
                if config.digest != *expected_image_digest {
                    continue;
                }

                let Some(content_digest) = response_headers
                    .get(DOCKER_CONTENT_DIGEST_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                else {
                    continue;
                };

                return Ok(content_digest);
            }
        }
    }

    Err(LauncherError::ImageHashNotFoundAmongTags)
}

/// Returns if the given image digest is valid (pull + manifest + digest match).
///    Does NOT extend RTMR3 and does NOT run the container.
async fn validate_image_hash(
    launcher_config: &LauncherConfig,
    image_hash: DockerSha256Digest,
) -> Result<(), ImageDigestValidationFailed> {
    let manifest_digest = get_manifest_digest(launcher_config, &image_hash)
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

    // Verify digest
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

    let pulled_digest = String::from_utf8_lossy(&inspect.stdout)
        .trim()
        .to_string()
        .parse()
        .expect("is valid digest");

    if pulled_digest != image_hash {
        return Err(
            ImageDigestValidationFailed::PulledImageHasMismatchedDigest {
                pulled_digest,
                expected_digest: image_hash,
            },
        );
    }

    Ok(())
}

fn render_compose_file(
    platform: Platform,
    mpc_config_file: &std::path::Path,
    docker_flags: &DockerLaunchFlags,
    image_digest: &DockerSha256Digest,
) -> Result<tempfile::NamedTempFile, LauncherError> {
    let template = match platform {
        Platform::Tee => COMPOSE_TEE_TEMPLATE,
        Platform::NonTee => COMPOSE_TEMPLATE,
    };

    let ports: Vec<String> = docker_flags
        .port_mappings
        .ports
        .iter()
        .map(PortMapping::docker_compose_value)
        .collect();
    let ports_json = serde_json::to_string(&ports).expect("port list is serializable");

    let rendered = template
        .replace("{{IMAGE}}", &image_digest.to_string())
        .replace("{{CONTAINER_NAME}}", MPC_CONTAINER_NAME)
        .replace(
            "{{MPC_CONFIG_HOST_PATH}}",
            &mpc_config_file.display().to_string(),
        )
        .replace("{{MPC_CONFIG_CONTAINER_PATH}}", MPC_CONFIG_CONTAINER_PATH)
        .replace("{{DSTACK_UNIX_SOCKET}}", DSTACK_UNIX_SOCKET)
        .replace("{{PORTS}}", &ports_json);

    tracing::info!(compose = %rendered, "rendered docker-compose file");

    let mut file = tempfile::NamedTempFile::new().map_err(LauncherError::TempFileCreate)?;
    file.write_all(rendered.as_bytes())
        .map_err(|source| LauncherError::FileWrite {
            path: file.path().display().to_string(),
            source,
        })?;

    Ok(file)
}

fn launch_mpc_container(
    platform: Platform,
    valid_hash: &DockerSha256Digest,
    mpc_config_file: &std::path::Path,
    docker_flags: &DockerLaunchFlags,
) -> Result<(), LauncherError> {
    tracing::info!("Launching MPC node with validated hash: {valid_hash}",);

    let compose_file = render_compose_file(platform, mpc_config_file, docker_flags, valid_hash)?;
    let compose_path = compose_file.path().display().to_string();

    // Remove any existing container from a previous run (by name, independent of compose file)
    let _ = Command::new("docker")
        .args(["rm", "-f", MPC_CONTAINER_NAME])
        .output();

    let run_output = Command::new("docker")
        .args(["compose", "-f", &compose_path, "up", "-d"])
        .output()
        .map_err(|inner| LauncherError::DockerRunFailed {
            image_hash: valid_hash.clone(),
            inner,
        })?;

    if !run_output.status.success() {
        let stderr = String::from_utf8_lossy(&run_output.stderr);
        let stdout = String::from_utf8_lossy(&run_output.stdout);
        tracing::error!(%stderr, %stdout, "docker compose up failed");
        return Err(LauncherError::DockerRunFailedExitStatus {
            image_hash: valid_hash.clone(),
            output: stderr.into_owned(),
        });
    }

    tracing::info!("MPC launched successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use assert_matches::assert_matches;
    use launcher_interface::types::{ApprovedHashes, DockerSha256Digest};
    use near_mpc_bounded_collections::NonEmptyVec;

    use crate::constants::*;
    use crate::error::LauncherError;
    use crate::render_compose_file;
    use crate::select_image_hash;
    use crate::types::*;

    const SAMPLE_CONFIG_PATH: &str = "/tapp/mpc-config.json";

    fn render(
        platform: Platform,
        config_path: &str,
        flags: &DockerLaunchFlags,
        digest: &DockerSha256Digest,
    ) -> String {
        let file = render_compose_file(platform, Path::new(config_path), flags, digest).unwrap();
        std::fs::read_to_string(file.path()).unwrap()
    }

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

    fn approved_file(hashes: Vec<DockerSha256Digest>) -> ApprovedHashes {
        ApprovedHashes {
            approved_hashes: NonEmptyVec::from_vec(hashes).unwrap(),
        }
    }

    fn empty_docker_flags() -> DockerLaunchFlags {
        serde_json::from_value(serde_json::json!({
            "port_mappings": {"ports": []}
        }))
        .unwrap()
    }

    fn docker_flags_with_port() -> DockerLaunchFlags {
        serde_json::from_value(serde_json::json!({
            "port_mappings": {"ports": [{"src": 11780, "dst": 11780}]}
        }))
        .unwrap()
    }

    #[test]
    fn tee_mode_includes_dstack_env_and_volume() {
        // given
        let flags = empty_docker_flags();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::Tee, SAMPLE_CONFIG_PATH, &flags, &digest);

        // then
        assert!(rendered.contains(&format!("DSTACK_ENDPOINT={DSTACK_UNIX_SOCKET}")));
        assert!(rendered.contains(&format!("{DSTACK_UNIX_SOCKET}:{DSTACK_UNIX_SOCKET}")));
    }

    #[test]
    fn nontee_mode_excludes_dstack() {
        // given
        let flags = empty_docker_flags();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, SAMPLE_CONFIG_PATH, &flags, &digest);

        // then
        assert!(!rendered.contains("DSTACK_ENDPOINT"));
        assert!(!rendered.contains(DSTACK_UNIX_SOCKET));
    }

    #[test]
    fn includes_security_opts_and_required_volumes() {
        // given
        let flags = empty_docker_flags();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, SAMPLE_CONFIG_PATH, &flags, &digest);

        // then
        assert!(rendered.contains("no-new-privileges:true"));
        assert!(rendered.contains("/tapp:/tapp:ro"));
        assert!(rendered.contains("shared-volume:/mnt/shared"));
        assert!(rendered.contains("mpc-data:/data"));
        assert!(rendered.contains(&format!("container_name: \"{MPC_CONTAINER_NAME}\"")));
    }

    #[test]
    fn mounts_config_file_read_only() {
        // given
        let flags = empty_docker_flags();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, SAMPLE_CONFIG_PATH, &flags, &digest);

        // then
        assert!(rendered.contains(&format!(
            "{SAMPLE_CONFIG_PATH}:{MPC_CONFIG_CONTAINER_PATH}:ro"
        )));
    }

    #[test]
    fn includes_start_with_config_file_command() {
        // given
        let flags = empty_docker_flags();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, SAMPLE_CONFIG_PATH, &flags, &digest);

        // then
        assert!(rendered.contains("start-with-config-file"));
        assert!(rendered.contains(MPC_CONFIG_CONTAINER_PATH));
    }

    #[test]
    fn image_is_set() {
        // given
        let flags = empty_docker_flags();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, SAMPLE_CONFIG_PATH, &flags, &digest);

        // then
        assert!(rendered.contains(&format!("image: \"{digest}\"")));
    }

    #[test]
    fn includes_ports() {
        // given
        let flags = docker_flags_with_port();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, SAMPLE_CONFIG_PATH, &flags, &digest);

        // then
        assert!(rendered.contains("11780:11780"));
    }

    #[test]
    fn no_env_section_in_nontee_mode() {
        // given
        let flags = empty_docker_flags();
        let digest = sample_digest();

        // when
        let rendered = render(Platform::NonTee, SAMPLE_CONFIG_PATH, &flags, &digest);

        // then
        assert!(!rendered.contains("environment:"));
    }

    // --- select_image_hash ---

    #[test]
    fn select_hash_override_present_and_in_approved_list() {
        // given
        let override_digest = digest('b');
        let approved = approved_file(vec![digest('c'), override_digest.clone(), digest('d')]);

        // when
        let result = select_image_hash(Some(&approved), &digest('f'), Some(&override_digest));

        // then
        assert_matches!(result, Ok(selected) => {
            assert_eq!(selected, override_digest);
        });
    }

    #[test]
    fn select_hash_override_not_in_approved_list() {
        // given
        let override_digest = digest('b');
        let approved = approved_file(vec![digest('c'), digest('d')]);

        // when
        let result = select_image_hash(Some(&approved), &digest('f'), Some(&override_digest));

        // then
        assert_matches!(result, Err(LauncherError::InvalidHashOverride(_)));
    }

    #[test]
    fn select_hash_no_override_picks_newest() {
        // given - first entry is "newest"
        let newest = digest('a');
        let approved = approved_file(vec![newest.clone(), digest('b'), digest('c')]);

        // when
        let result = select_image_hash(Some(&approved), &digest('f'), None);

        // then
        assert_matches!(result, Ok(selected) => {
            assert_eq!(selected, newest);
        });
    }

    #[test]
    fn select_hash_missing_file_falls_back_to_default() {
        // given
        let default = digest('d');

        // when
        let result = select_image_hash(None, &default, None);

        // then
        assert_matches!(result, Ok(selected) => {
            assert_eq!(selected, default);
        });
    }

    #[test]
    fn select_hash_missing_file_ignores_override() {
        // given - override is set but file is missing, so default wins
        let default = digest('d');
        let override_digest = digest('b');

        // when
        let result = select_image_hash(None, &default, Some(&override_digest));

        // then
        assert_matches!(result, Ok(selected) => {
            assert_eq!(selected, default);
        });
    }

    // --- approved_hashes JSON key alignment ---

    #[test]
    fn approved_hashes_json_key_is_approved_hashes() {
        // given - the JSON field name must match between launcher and MPC node
        let file = approved_file(vec![sample_digest()]);

        // when
        let json = serde_json::to_value(&file).unwrap();

        // then
        assert!(json.get("approved_hashes").is_some());
    }
}

/// Integration tests requiring network access and Docker Hub.
/// Run with: cargo test -p tee-launcher --features integration-test
#[cfg(all(test, feature = "integration-test"))]
mod integration_tests {
    use super::*;
    use assert_matches::assert_matches;

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
        }
    }

    #[tokio::test]
    async fn get_manifest_digest_resolves_known_image() {
        // given
        let config = test_launcher_config();
        let expected_digest: DockerSha256Digest = TEST_DIGEST.parse().unwrap();

        // when
        let result = get_manifest_digest(&config, &expected_digest).await;

        // then
        assert!(result.is_ok(), "get_manifest_digest failed: {result:?}");
    }

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
