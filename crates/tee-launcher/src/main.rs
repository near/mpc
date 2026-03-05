// A rewrite of launcher.py

use std::process::Command;
use std::{collections::VecDeque, time::Duration};

use backon::{ExponentialBuilder, Retryable};
use clap::Parser;
use launcher_interface::MPC_IMAGE_HASH_EVENT;
use launcher_interface::types::{ApprovedHashesFile, DockerSha256Digest};

use constants::*;
use docker_types::*;
use error::*;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue};
use types::*;
use url::Url;

mod constants;
mod docker_types;
mod env_validation;
mod error;
mod types;

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

    // Load dstack user config
    let config_file = std::fs::OpenOptions::new()
        .read(true)
        .open(DSTACK_USER_CONFIG_FILE)
        .map_err(|source| LauncherError::FileRead {
            path: DSTACK_USER_CONFIG_FILE.to_string(),
            source,
        })?;

    let dstack_config: Config =
        serde_json::from_reader(config_file).map_err(|source| LauncherError::JsonParse {
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

    let image_hash: DockerSha256Digest = {
        match approved_hashes_file {
            Err(err) => {
                let default_image_digest = args.default_image_digest;
                tracing::warn!(
                    ?err,
                    ?default_image_digest,
                    "approved hashes file does not exist on disk, falling back to default digest"
                );
                default_image_digest
            }
            Ok(approved_hashes_file) => {
                let approved_hashes_on_disk: ApprovedHashesFile =
                    serde_json::from_reader(approved_hashes_file).map_err(|source| {
                        LauncherError::JsonParse {
                            path: IMAGE_DIGEST_FILE.to_string(),
                            source,
                        }
                    })?;

                if let Some(override_image) = &dstack_config.launcher_config.mpc_hash_override {
                    tracing::info!(?override_image, "override mpc image hash provided");

                    let override_image_is_allowed = approved_hashes_on_disk
                        .approved_hashes
                        .contains(override_image);

                    if !override_image_is_allowed {
                        return Err(LauncherError::InvalidHashOverride(format!(
                            "MPC_HASH_OVERRIDE={override_image} does not match any approved hash",
                        )));
                    }

                    override_image.clone()
                } else {
                    approved_hashes_on_disk.newest_approved_hash().clone()
                }
            }
        }
    };

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

    launch_mpc_container(
        args.platform,
        &image_hash,
        &dstack_config.mpc_passthrough_env,
        &dstack_config.docker_command_config,
    )?;

    Ok(())
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

fn docker_run_args(
    platform: Platform,
    mpc_config: &MpcBinaryConfig,
    docker_flags: &DockerLaunchFlags,
    image_digest: &DockerSha256Digest,
) -> Result<Vec<String>, LauncherError> {
    let mut cmd: Vec<String> = vec![];

    // Required environment variables
    cmd.extend([
        "--env".into(),
        format!("MPC_IMAGE_HASH={}", image_digest.as_raw_hex()),
    ]);
    cmd.extend([
        "--env".into(),
        format!("MPC_LATEST_ALLOWED_HASH_FILE={IMAGE_DIGEST_FILE}"),
    ]);

    if platform == Platform::Tee {
        cmd.extend([
            "--env".into(),
            format!("DSTACK_ENDPOINT={DSTACK_UNIX_SOCKET}"),
        ]);
        cmd.extend([
            "-v".into(),
            format!("{DSTACK_UNIX_SOCKET}:{DSTACK_UNIX_SOCKET}"),
        ]);
    }

    for (key, value) in mpc_config.env_vars()? {
        cmd.extend(["--env".into(), format!("{key}={value}")]);
    }

    cmd.extend(docker_flags.extra_hosts.docker_args());
    cmd.extend(docker_flags.port_mappings.docker_args());

    // Container run configuration
    cmd.extend([
        "--security-opt".into(),
        "no-new-privileges:true".into(),
        "-v".into(),
        "/tapp:/tapp:ro".into(),
        "-v".into(),
        "shared-volume:/mnt/shared".into(),
        "-v".into(),
        "mpc-data:/data".into(),
        "--name".into(),
        MPC_CONTAINER_NAME.into(),
        "--detach".into(),
        image_digest.to_string(),
    ]);

    let docker_command_string = cmd.join(" ");
    tracing::info!(?docker_command_string, "docker cmd");

    // Final LD_PRELOAD safeguard
    if docker_command_string.contains("LD_PRELOAD") {
        return Err(LauncherError::LdPreloadDetected);
    }

    Ok(cmd)
}

fn launch_mpc_container(
    platform: Platform,
    valid_hash: &DockerSha256Digest,
    mpc_config: &MpcBinaryConfig,
    docker_flags: &DockerLaunchFlags,
) -> Result<(), LauncherError> {
    tracing::info!("Launching MPC node with validated hash: {valid_hash}",);

    // shutdown container if one is already running
    let _ = Command::new("docker")
        .args(["rm", "-f", MPC_CONTAINER_NAME])
        .output();

    let docker_run_args = docker_run_args(platform, mpc_config, docker_flags, valid_hash)?;

    let run_output = Command::new("docker")
        .arg("run")
        .args(&docker_run_args)
        .output()
        .map_err(|inner| LauncherError::DockerRunFailed {
            image_hash: valid_hash.clone(),
            inner,
        })?;

    if !run_output.status.success() {
        let stderr = String::from_utf8_lossy(&run_output.stderr);
        let stdout = String::from_utf8_lossy(&run_output.stdout);
        tracing::error!(%stderr, %stdout, "docker run failed");
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
    use std::collections::BTreeMap;

    use assert_matches::assert_matches;
    use launcher_interface::types::DockerSha256Digest;

    use crate::constants::*;
    use crate::docker_run_args;
    use crate::error::LauncherError;
    use crate::types::*;

    fn sample_digest() -> DockerSha256Digest {
        format!("sha256:{}", "a".repeat(64)).parse().unwrap()
    }

    fn base_mpc_config() -> MpcBinaryConfig {
        MpcBinaryConfig {
            mpc_account_id: "test-account".into(),
            mpc_local_address: "127.0.0.1".parse().unwrap(),
            mpc_secret_key_store: "secret".into(),
            mpc_backup_encryption_key_hex: "0".repeat(64),
            mpc_env: MpcEnv::Testnet,
            mpc_home_dir: "/data".into(),
            mpc_contract_id: "contract.near".into(),
            mpc_responder_id: "responder-1".into(),
            near_boot_nodes: "boot1,boot2".into(),
            rust_backtrace: RustBacktrace::Enabled,
            rust_log: RustLog::Level(RustLogLevel::Info),
            extra_env: BTreeMap::new(),
        }
    }

    fn empty_docker_flags() -> DockerLaunchFlags {
        serde_json::from_value(serde_json::json!({
            "extra_hosts": {"hosts": []},
            "port_mappings": {"ports": []}
        }))
        .unwrap()
    }

    fn docker_flags_with_host_and_port() -> DockerLaunchFlags {
        serde_json::from_value(serde_json::json!({
            "extra_hosts": {"hosts": [{"hostname": {"Domain": "node1"}, "ip": "192.168.1.1"}]},
            "port_mappings": {"ports": [{"src": 11780, "dst": 11780}]}
        }))
        .unwrap()
    }

    #[test]
    fn tee_mode_includes_dstack_mount() {
        // given
        let config = base_mpc_config();
        let flags = empty_docker_flags();
        let digest = sample_digest();

        // when
        let args = docker_run_args(Platform::Tee, &config, &flags, &digest).unwrap();

        // then
        let joined = args.join(" ");
        assert!(joined.contains(&format!("DSTACK_ENDPOINT={DSTACK_UNIX_SOCKET}")));
        assert!(joined.contains(&format!("{DSTACK_UNIX_SOCKET}:{DSTACK_UNIX_SOCKET}")));
    }

    #[test]
    fn nontee_mode_excludes_dstack_mount() {
        // given
        let config = base_mpc_config();
        let flags = empty_docker_flags();
        let digest = sample_digest();

        // when
        let args = docker_run_args(Platform::NonTee, &config, &flags, &digest).unwrap();

        // then
        let joined = args.join(" ");
        assert!(!joined.contains("DSTACK_ENDPOINT="));
        assert!(!joined.contains(&format!("{DSTACK_UNIX_SOCKET}:{DSTACK_UNIX_SOCKET}")));
    }

    #[test]
    fn includes_security_opts_and_required_volumes() {
        // given
        let config = base_mpc_config();
        let flags = empty_docker_flags();
        let digest = sample_digest();

        // when
        let args = docker_run_args(Platform::NonTee, &config, &flags, &digest).unwrap();

        // then
        let joined = args.join(" ");
        assert!(joined.contains("--security-opt no-new-privileges:true"));
        assert!(joined.contains("/tapp:/tapp:ro"));
        assert!(joined.contains("shared-volume:/mnt/shared"));
        assert!(joined.contains("mpc-data:/data"));
        assert!(joined.contains(&format!("--name {MPC_CONTAINER_NAME}")));
        assert!(joined.contains("--detach"));
    }

    #[test]
    fn image_digest_is_last_argument() {
        // given
        let config = base_mpc_config();
        let flags = empty_docker_flags();
        let digest = sample_digest();

        // when
        let args = docker_run_args(Platform::NonTee, &config, &flags, &digest).unwrap();

        // then
        assert_eq!(args.last().unwrap(), &digest.to_string());
    }

    #[test]
    fn includes_ports_and_extra_hosts() {
        // given
        let config = base_mpc_config();
        let flags = docker_flags_with_host_and_port();
        let digest = sample_digest();

        // when
        let args = docker_run_args(Platform::NonTee, &config, &flags, &digest).unwrap();

        // then
        let joined = args.join(" ");
        assert!(joined.contains("--add-host node1:192.168.1.1"));
        assert!(joined.contains("-p 11780:11780"));
    }

    #[test]
    fn includes_mpc_env_vars() {
        // given
        let config = base_mpc_config();
        let flags = empty_docker_flags();
        let digest = sample_digest();

        // when
        let args = docker_run_args(Platform::NonTee, &config, &flags, &digest).unwrap();

        // then
        let joined = args.join(" ");
        assert!(joined.contains("MPC_ACCOUNT_ID=test-account"));
        assert!(joined.contains("MPC_IMAGE_HASH="));
        assert!(joined.contains(&format!("MPC_LATEST_ALLOWED_HASH_FILE={IMAGE_DIGEST_FILE}")));
    }

    #[test]
    fn ld_preload_in_typed_field_is_rejected_by_env_validation() {
        // given - typed fields are also validated by env_validation::validate_env_value,
        // so LD_PRELOAD in any env value is caught before the final safeguard.
        let mut config = base_mpc_config();
        config.mpc_account_id = "LD_PRELOAD=/evil.so".into();
        let flags = empty_docker_flags();
        let digest = sample_digest();

        // when
        let result = docker_run_args(Platform::NonTee, &config, &flags, &digest);

        // then
        assert_matches!(result, Err(LauncherError::UnsafeEnvValue { .. }));
    }
}
