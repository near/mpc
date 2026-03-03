use std::collections::{BTreeMap, VecDeque};
use std::process::Command;
use std::sync::LazyLock;

use clap::Parser;
use launcher_interface::types::ApprovedHashesFile;
use regex::Regex;
use std::os::unix::fs::FileTypeExt as _;

// Reuse the workspace hash type for type-safe image hash handling.
use mpc_primitives::hash::MpcDockerImageHash;

use contants::*;
use error::*;
use types::*;

mod contants;
mod error;
mod types;

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
        .expect("dstack user config file exists");

    let dstack_config: Config = serde_json::from_reader(config_file).expect("config file is valid");

    let image_hash: MpcDockerImageHash = {
        match dstack_config.launcher_config.mpc_hash_override.clone() {
            Some(override_hash) => override_hash,
            None => {
                let approved_hashes_file = std::fs::OpenOptions::new()
                    .read(true)
                    .open(IMAGE_DIGEST_FILE)
                    .map_err(|source| LauncherError::FileRead {
                        path: IMAGE_DIGEST_FILE.to_string(),
                        source,
                    })?;

                let approved_hashes_on_disk: ApprovedHashesFile =
                    serde_json::from_reader(approved_hashes_file).map_err(|source| {
                        LauncherError::JsonParse {
                            path: IMAGE_DIGEST_FILE.to_string(),
                            source,
                        }
                    })?;

                approved_hashes_on_disk.newest_approved_hash().clone()
            }
        }
    };

    let () = check_image_digest_exists_on_docker_hub(image_hash)?;

    if args.platform == Platform::Tee {
        extend_rtmr3(&image_hash).await?;
    }

    launch_mpc_container(
        args.platform,
        &selected_hash,
        &dstack_config.mpc_passthrough_env,
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Constants — matching Python launcher exactly
// ---------------------------------------------------------------------------

// Regex patterns (compiled once)
static MPC_ENV_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^MPC_[A-Z0-9_]{1,64}$").unwrap());
static HOST_ENTRY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9\-\.]+:\d{1,3}(\.\d{1,3}){3}$").unwrap());
static PORT_MAPPING_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d{1,5}):(\d{1,5})$").unwrap());
static INVALID_HOST_ENTRY_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[;&|`$\\<>\-]|^--").unwrap());

// Denied env keys — never pass these to the container
const DENIED_CONTAINER_ENV_KEYS: &[&str] = &["MPC_P2P_PRIVATE_KEY", "MPC_ACCOUNT_SK"];

// Allowed non-MPC env vars (backward compatibility)
const ALLOWED_MPC_ENV_VARS: &[&str] = &[
    "MPC_ACCOUNT_ID",
    "MPC_LOCAL_ADDRESS",
    "MPC_SECRET_STORE_KEY",
    "MPC_CONTRACT_ID",
    "MPC_ENV",
    "MPC_HOME_DIR",
    "NEAR_BOOT_NODES",
    "RUST_BACKTRACE",
    "RUST_LOG",
    "MPC_RESPONDER_ID",
    "MPC_BACKUP_ENCRYPTION_KEY_HEX",
];

// ---------------------------------------------------------------------------
// Validation functions — security policy for env passthrough
// ---------------------------------------------------------------------------

fn has_control_chars(s: &str) -> bool {
    let control_chars = ['\n', '\r', '\0'];

    for character in s.chars() {
        if control_chars.contains(&character) {
            return true;
        }
        if (character as u32) < 0x20 && character != '\t' {
            return true;
        }
    }
    false
}

fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::Ipv4Addr>().is_ok()
}

fn is_valid_host_entry(entry: &str) -> bool {
    if !HOST_ENTRY_RE.is_match(entry) {
        return false;
    }
    if let Some((_host, ip)) = entry.rsplit_once(':') {
        is_valid_ip(ip)
    } else {
        false
    }
}

fn is_valid_port_mapping(entry: &str) -> bool {
    if let Some(caps) = PORT_MAPPING_RE.captures(entry) {
        let host_port: u32 = caps[1].parse().unwrap_or(0);
        let container_port: u32 = caps[2].parse().unwrap_or(0);
        host_port > 0 && host_port <= 65535 && container_port > 0 && container_port <= 65535
    } else {
        false
    }
}

fn is_safe_host_entry(entry: &str) -> bool {
    if INVALID_HOST_ENTRY_PATTERN.is_match(entry) {
        return false;
    }
    if entry.contains("LD_PRELOAD") {
        return false;
    }
    true
}

fn is_safe_port_mapping(mapping: &str) -> bool {
    !INVALID_HOST_ENTRY_PATTERN.is_match(mapping)
}

// ---------------------------------------------------------------------------
// Docker registry communication
// ---------------------------------------------------------------------------

// TODO: Use backon
async fn request_until_success(
    client: &reqwest::Client,
    url: &str,
    headers: &[(String, String)],
    config: &LauncherConfig,
) -> Result<reqwest::Response> {
    let mut interval = config.rpc_request_interval_secs as f64;

    for attempt in 1..=config.rpc_max_attempts {
        // Sleep before request (matching Python behavior)
        tokio::time::sleep(std::time::Duration::from_secs_f64(interval)).await;
        interval = (interval.max(1.0) * 1.5).min(60.0);

        let mut req = client.get(url);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }

        match req
            .timeout(std::time::Duration::from_secs(
                config.rpc_request_timeout_secs,
            ))
            .send()
            .await
        {
            Err(e) => {
                tracing::warn!(
                    "Attempt {attempt}/{}: Failed to fetch {url}. Status: Timeout/Error: {e}",
                    config.rpc_max_attempts
                );
                continue;
            }
            Ok(resp) if resp.status() != reqwest::StatusCode::OK => {
                tracing::warn!(
                    "Attempt {attempt}/{}: Failed to fetch {url}. Status: {}",
                    config.rpc_max_attempts,
                    resp.status()
                );
                continue;
            }
            Ok(resp) => return Ok(resp),
        }
    }

    Err(LauncherError::RegistryRequestFailed {
        url: url.to_string(),
        attempts: config.rpc_max_attempts,
    })
}

async fn get_manifest_digest(config: &LauncherConfig) -> Result<String> {
    let tags = config.image_tags.clone();

    let token_url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
        config.image_name
    );

    let client = reqwest::Client::new();
    let token_resp = client
        .get(&token_url)
        .send()
        .await
        .map_err(|e| LauncherError::RegistryAuthFailed(e.to_string()))?;
    if token_resp.status() != reqwest::StatusCode::OK {
        return Err(LauncherError::RegistryAuthFailed(format!(
            "status: {}",
            token_resp.status()
        )));
    }
    let token_json: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| LauncherError::RegistryAuthFailed(e.to_string()))?;
    let token = token_json["token"]
        .as_str()
        .ok_or_else(|| LauncherError::RegistryAuthFailed("no token in response".to_string()))?
        .to_string();

    let mut tags: VecDeque<String> = tags.into_iter().collect();

    while let Some(tag) = tags.pop_front() {
        let manifest_url = format!(
            "https://{}/v2/{}/manifests/{tag}",
            config.registry, config.image_name
        );
        let headers = vec![
            (
                "Accept".to_string(),
                "application/vnd.docker.distribution.manifest.v2+json".to_string(),
            ),
            ("Authorization".to_string(), format!("Bearer {token}")),
        ];

        match request_until_success(&client, &manifest_url, &headers, config).await {
            Ok(resp) => {
                let content_digest = resp
                    .headers()
                    .get("Docker-Content-Digest")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let manifest: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| LauncherError::RegistryResponseParse(e.to_string()))?;

                let media_type = manifest["mediaType"].as_str().unwrap_or("");
                match media_type {
                    "application/vnd.oci.image.index.v1+json" => {
                        // Multi-platform manifest; scan for amd64/linux
                        if let Some(manifests) = manifest["manifests"].as_array() {
                            for m in manifests {
                                let arch = m["platform"]["architecture"].as_str().unwrap_or("");
                                let os = m["platform"]["os"].as_str().unwrap_or("");
                                if arch == "amd64" && os == "linux" {
                                    if let Some(digest) = m["digest"].as_str() {
                                        tags.push_back(digest.to_string());
                                    }
                                }
                            }
                        }
                    }
                    // TODO:
                    // "application/vnd.docker.distribution.manifest.v2+json"
                    // | "application/vnd.oci.image.manifest.v1+json" => {
                    //     let config_digest = manifest["config"]["digest"].as_str().unwrap_or("");
                    //     if config_digest == config. {
                    //         if let Some(digest) = content_digest {
                    //             return Ok(digest);
                    //         }
                    //     }
                    // }
                    _ => {}
                }
            }
            Err(e) => {
                tracing::warn!(
                    "{e}: Exceeded number of maximum RPC requests for any given attempt. \
                     Will continue in the hopes of finding the matching image hash among remaining tags"
                );
            }
        }
    }

    Err(LauncherError::ImageHashNotFoundAmongTags)
}

fn check_image_digest_exists_on_docker_hub(
    image_hash: MpcDockerImageHash,
) -> Result<(), ImageDigestValidationFailed> {
    let image_hash_name = format!("sha256:{}", image_hash.as_hex());

    // Pull
    let pull = Command::new("docker")
        .args(["pull", &image_hash_name])
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
            &image_hash_name,
        ])
        .output()
        .map_err(|e| ImageDigestValidationFailed::DockerInspectFailed(e.to_string()))?;

    let docker_inspect_failed = !inspect.status.success();
    if docker_inspect_failed {
        return Err(ImageDigestValidationFailed::DockerPullFailed(
            "docker inspect terminated with unsuccessful status".to_string(),
        ));
    }

    let pulled_digest = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
    if pulled_digest != image_hash_name {
        return Err(
            ImageDigestValidationFailed::PulledImageHasMismatchedDigest {
                pulled_digest,
                expected_digest: image_hash_name,
            },
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Docker command builder
// ---------------------------------------------------------------------------

fn remove_existing_container() {
    let output = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}"])
        .output();

    match output {
        Ok(output) => {
            let names = String::from_utf8_lossy(&output.stdout);

            if names.lines().any(|n| n == MPC_CONTAINER_NAME) {
                tracing::info!("Removing existing container: {MPC_CONTAINER_NAME}");
                let _ = Command::new("docker")
                    .args(["rm", "-f", MPC_CONTAINER_NAME])
                    .output();
            }
        }
        Err(error) => {
            tracing::warn!("Failed to check/remove container {MPC_CONTAINER_NAME}: {error}");
        }
    }
}

fn build_docker_cmd(
    platform: Platform,
    mpc_config: &MpcBinaryConfig,
    image_digest: &MpcDockerImageHash,
) -> Result<Vec<String>> {
    let mut cmd: Vec<String> = vec!["docker".into(), "run".into()];

    // Required environment variables
    cmd.extend([
        "--env".into(),
        format!("MPC_IMAGE_HASH={}", image_digest.as_hex()),
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

    // Track env passthrough size/caps
    let mut passed_env_count: usize = 0;
    let mut total_env_bytes: usize = 0;

    // // BTreeMap iteration is already sorted by key (deterministic)
    // for (key, value) in mpc_config {
    //     if key == "EXTRA_HOSTS" {
    //         for host_entry in value.split(',') {
    //             let clean = host_entry.trim();
    //             if is_safe_host_entry(clean) && is_valid_host_entry(clean) {
    //                 cmd.extend(["--add-host".into(), clean.to_string()]);
    //             } else {
    //                 tracing::warn!("Ignoring invalid or unsafe EXTRA_HOSTS entry: {clean}");
    //             }
    //         }
    //         continue;
    //     }

    //     passed_env_count += 1;
    //     if passed_env_count > MAX_PASSTHROUGH_ENV_VARS {
    //         return Err(LauncherError::TooManyEnvVars(MAX_PASSTHROUGH_ENV_VARS));
    //     }

    //     total_env_bytes += key.len() + 1 + value.len();
    //     if total_env_bytes > MAX_TOTAL_ENV_BYTES {
    //         return Err(LauncherError::EnvPayloadTooLarge(MAX_TOTAL_ENV_BYTES));
    //     }

    //     cmd.extend(["--env".into(), format!("{key}={value}")]);
    // }

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
        image_digest.as_hex(),
    ]);

    tracing::info!("docker cmd {}", cmd.join(" "));

    // Final LD_PRELOAD safeguard
    let cmd_str = cmd.join(" ");
    if cmd_str.contains("LD_PRELOAD") {
        return Err(LauncherError::LdPreloadDetected);
    }

    Ok(cmd)
}

fn launch_mpc_container(
    platform: Platform,
    valid_hash: &MpcDockerImageHash,
    mpc_config: &MpcBinaryConfig,
) -> Result<()> {
    tracing::info!(
        "Launching MPC node with validated hash: {}",
        valid_hash.as_hex()
    );

    remove_existing_container();
    let docker_cmd = build_docker_cmd(platform, mpc_config, valid_hash)?;

    let status = Command::new(&docker_cmd[0])
        .args(&docker_cmd[1..])
        .status()
        .map_err(|e| LauncherError::DockerRunFailed(valid_hash.clone()))?;

    if !status.success() {
        return Err(LauncherError::DockerRunFailed(valid_hash.clone()));
    }

    tracing::info!("MPC launched successfully.");
    Ok(())
}

async fn extend_rtmr3(image_hash: &MpcDockerImageHash) -> Result<(), LauncherError> {
    tracing::info!(?image_hash, "extending RTMR3");

    let dstack_cient = dstack_sdk::dstack_client::DstackClient::new(Some(DSTACK_UNIX_SOCKET));

    // GetQuote first
    dstack_cient
        .get_quote(vec![])
        .await
        .map_err(|e| LauncherError::DstackGetQuoteFailed(e.to_string()))?;

    // EmitEvent with the image digest
    dstack_cient
        .emit_event(
            "mpc-image-digest".to_string(),
            image_hash.as_hex().into_bytes(),
        )
        .await
        .map_err(|e| LauncherError::DstackEmitEventFailed(e.to_string()))?;

    Ok(())
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use assert_matches::assert_matches;
//     use launcher_interface::types::ApprovedHashesFile;

//     // -- DstackUserConfig parsing tests -------------------------------------

//     #[test]
//     fn test_user_config_defaults_when_map_is_empty() {
//         let config = user_config_from_map(BTreeMap::new()).unwrap();
//         assert_eq!(config.image_tags, vec![DEFAULT_MPC_IMAGE_TAG]);
//         assert_eq!(config.image_name, DEFAULT_MPC_IMAGE_NAME);
//         assert_eq!(config.registry, DEFAULT_MPC_REGISTRY);
//         assert_eq!(
//             config.rpc_request_timeout_secs,
//             DEFAULT_RPC_REQUEST_TIMEOUT_SECS
//         );
//         assert_eq!(
//             config.rpc_request_interval_secs,
//             DEFAULT_RPC_REQUEST_INTERVAL_SECS
//         );
//         assert_eq!(config.rpc_max_attempts, DEFAULT_RPC_MAX_ATTEMPTS);
//         assert!(config.mpc_hash_override.is_none());
//         assert!(config.passthrough_env.is_empty());
//     }

//     #[test]
//     fn test_user_config_typed_fields_extracted_from_map() {
//         let map = BTreeMap::from([
//             (
//                 DSTACK_USER_CONFIG_MPC_IMAGE_TAGS.into(),
//                 "v1.0, v1.1".into(),
//             ),
//             (DSTACK_USER_CONFIG_MPC_IMAGE_NAME.into(), "my/image".into()),
//             (
//                 DSTACK_USER_CONFIG_MPC_IMAGE_REGISTRY.into(),
//                 "my.registry.io".into(),
//             ),
//             (ENV_VAR_RPC_REQUEST_TIMEOUT_SECS.into(), "30.0".into()),
//             (ENV_VAR_RPC_MAX_ATTEMPTS.into(), "5".into()),
//             ("MPC_ACCOUNT_ID".into(), "account.near".into()),
//         ]);
//         let config = user_config_from_map(map).unwrap();
//         assert_eq!(config.image_tags, vec!["v1.0", "v1.1"]);
//         assert_eq!(config.image_name, "my/image");
//         assert_eq!(config.registry, "my.registry.io");
//         assert_eq!(config.rpc_request_timeout_secs, 30.0);
//         assert_eq!(config.rpc_max_attempts, 5);
//         // Launcher-only keys are NOT in passthrough_env
//         assert!(
//             !config
//                 .passthrough_env
//                 .contains_key(DSTACK_USER_CONFIG_MPC_IMAGE_TAGS)
//         );
//         assert!(
//             !config
//                 .passthrough_env
//                 .contains_key(ENV_VAR_RPC_MAX_ATTEMPTS)
//         );
//         // Container passthrough keys ARE in passthrough_env
//         assert_eq!(
//             config.passthrough_env.get("MPC_ACCOUNT_ID").unwrap(),
//             "account.near"
//         );
//     }

//     #[test]
//     fn test_user_config_malformed_rpc_fields_error() {
//         let map = BTreeMap::from([(ENV_VAR_RPC_MAX_ATTEMPTS.into(), "not_a_number".into())]);
//         let err = user_config_from_map(map).unwrap_err();
//         assert_matches!(err, LauncherError::InvalidEnvVar { key, .. } if key == ENV_VAR_RPC_MAX_ATTEMPTS);

//         let map = BTreeMap::from([(ENV_VAR_RPC_REQUEST_TIMEOUT_SECS.into(), "bad".into())]);
//         let err = user_config_from_map(map).unwrap_err();
//         assert_matches!(err, LauncherError::InvalidEnvVar { key, .. } if key == ENV_VAR_RPC_REQUEST_TIMEOUT_SECS);

//         let map = BTreeMap::from([(ENV_VAR_RPC_REQUEST_INTERVAL_SECS.into(), "bad".into())]);
//         let err = user_config_from_map(map).unwrap_err();
//         assert_matches!(err, LauncherError::InvalidEnvVar { key, .. } if key == ENV_VAR_RPC_REQUEST_INTERVAL_SECS);
//     }

//     #[test]
//     fn test_user_config_hash_override_extracted() {
//         let map = BTreeMap::from([(ENV_VAR_MPC_HASH_OVERRIDE.into(), "sha256:abc".into())]);
//         let config = user_config_from_map(map).unwrap();
//         assert_eq!(config.mpc_hash_override.unwrap(), "sha256:abc");
//         assert!(
//             !config
//                 .passthrough_env
//                 .contains_key(ENV_VAR_MPC_HASH_OVERRIDE)
//         );
//     }

//     #[test]
//     fn test_parse_user_config_from_file() {
//         let dir = tempfile::tempdir().unwrap();
//         let file = dir.path().join("user_config");
//         std::fs::write(
//             &file,
//             "# comment\nMPC_ACCOUNT_ID=test\nMPC_IMAGE_NAME=my/image\n",
//         )
//         .unwrap();
//         let config = parse_user_config(file.to_str().unwrap()).unwrap();
//         assert_eq!(config.image_name, "my/image");
//         assert_eq!(
//             config.passthrough_env.get("MPC_ACCOUNT_ID").unwrap(),
//             "test"
//         );
//         assert!(!config.passthrough_env.contains_key("MPC_IMAGE_NAME"));
//     }

//     // -- Host/port validation tests -----------------------------------------

//     #[test]
//     fn test_valid_host_entry() {
//         assert!(is_valid_host_entry("node.local:192.168.1.1"));
//         assert!(!is_valid_host_entry("node.local:not-an-ip"));
//         assert!(!is_valid_host_entry("--env LD_PRELOAD=hack.so"));
//     }

//     #[test]
//     fn test_valid_port_mapping() {
//         assert!(is_valid_port_mapping("11780:11780"));
//         assert!(!is_valid_port_mapping("65536:11780"));
//         assert!(!is_valid_port_mapping("--volume /:/mnt"));
//     }

//     // -- Security validation tests ------------------------------------------

//     #[test]
//     fn test_has_control_chars_rejects_newline_and_cr() {
//         assert!(has_control_chars("a\nb"));
//         assert!(has_control_chars("a\rb"));
//     }

//     #[test]
//     fn test_has_control_chars_allows_tab() {
//         assert!(!has_control_chars("a\tb"));
//     }

//     #[test]
//     fn test_has_control_chars_rejects_other_control_chars() {
//         assert!(has_control_chars(&format!("a{}b", '\x1F')));
//     }

//     #[test]
//     fn test_is_safe_env_value_rejects_control_chars() {
//         assert!(!is_safe_env_value("ok\nno"));
//         assert!(!is_safe_env_value("ok\rno"));
//         assert!(!is_safe_env_value(&format!("ok{}no", '\x1F')));
//     }

//     #[test]
//     fn test_is_safe_env_value_rejects_ld_preload() {
//         assert!(!is_safe_env_value("LD_PRELOAD=/tmp/x.so"));
//         assert!(!is_safe_env_value("foo LD_PRELOAD bar"));
//     }

//     #[test]
//     fn test_is_safe_env_value_rejects_too_long() {
//         assert!(!is_safe_env_value(&"a".repeat(MAX_ENV_VALUE_LEN + 1)));
//         assert!(is_safe_env_value(&"a".repeat(MAX_ENV_VALUE_LEN)));
//     }

//     #[test]
//     fn test_is_allowed_container_env_key_allows_mpc_prefix_uppercase() {
//         assert!(is_allowed_container_env_key("MPC_FOO"));
//         assert!(is_allowed_container_env_key("MPC_FOO_123"));
//         assert!(is_allowed_container_env_key("MPC_A_B_C"));
//     }

//     #[test]
//     fn test_is_allowed_container_env_key_rejects_lowercase_or_invalid() {
//         assert!(!is_allowed_container_env_key("MPC_foo"));
//         assert!(!is_allowed_container_env_key("MPC-FOO"));
//         assert!(!is_allowed_container_env_key("MPC.FOO"));
//         assert!(!is_allowed_container_env_key("MPC_"));
//     }

//     #[test]
//     fn test_is_allowed_container_env_key_allows_compat_non_mpc_keys() {
//         assert!(is_allowed_container_env_key("RUST_LOG"));
//         assert!(is_allowed_container_env_key("RUST_BACKTRACE"));
//         assert!(is_allowed_container_env_key("NEAR_BOOT_NODES"));
//     }

//     #[test]
//     fn test_is_allowed_container_env_key_denies_sensitive_keys() {
//         assert!(!is_allowed_container_env_key("MPC_P2P_PRIVATE_KEY"));
//         assert!(!is_allowed_container_env_key("MPC_ACCOUNT_SK"));
//     }

//     // -- Docker cmd builder tests -------------------------------------------

//     fn make_digest() -> String {
//         format!("sha256:{}", "a".repeat(64))
//     }

//     fn base_env() -> BTreeMap<String, String> {
//         BTreeMap::from([
//             ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
//             ("MPC_CONTRACT_ID".into(), "contract.near".into()),
//             ("MPC_ENV".into(), "testnet".into()),
//             ("MPC_HOME_DIR".into(), "/data".into()),
//             ("NEAR_BOOT_NODES".into(), "boot1,boot2".into()),
//             ("RUST_LOG".into(), "info".into()),
//         ])
//     }

//     #[test]
//     fn test_build_docker_cmd_sanitizes_ports_and_hosts() {
//         let env = BTreeMap::from([
//             ("PORTS".into(), "11780:11780,--env BAD=1".into()),
//             (
//                 "EXTRA_HOSTS".into(),
//                 "node:192.168.1.1,--volume /:/mnt".into(),
//             ),
//             ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
//         ]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();

//         assert!(cmd.contains(&"MPC_ACCOUNT_ID=mpc-user-123".to_string()));
//         assert!(cmd.contains(&"11780:11780".to_string()));
//         assert!(cmd.contains(&"node:192.168.1.1".to_string()));
//         // Injection strings filtered
//         assert!(!cmd.iter().any(|arg| arg.contains("BAD=1")));
//         assert!(!cmd.iter().any(|arg| arg.contains("/:/mnt")));
//     }

//     #[test]
//     fn test_extra_hosts_does_not_allow_ld_preload() {
//         let env = BTreeMap::from([
//             (
//                 "EXTRA_HOSTS".into(),
//                 "host:1.2.3.4,--env LD_PRELOAD=/evil.so".into(),
//             ),
//             ("MPC_ACCOUNT_ID".into(), "safe".into()),
//         ]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         assert!(cmd.contains(&"host:1.2.3.4".to_string()));
//         assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
//     }

//     #[test]
//     fn test_ports_does_not_allow_volume_injection() {
//         let env = BTreeMap::from([
//             ("PORTS".into(), "2200:2200,--volume /:/mnt".into()),
//             ("MPC_ACCOUNT_ID".into(), "safe".into()),
//         ]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         assert!(cmd.contains(&"2200:2200".to_string()));
//         assert!(!cmd.iter().any(|arg| arg.contains("/:/mnt")));
//     }

//     #[test]
//     fn test_invalid_env_key_is_ignored() {
//         let env = BTreeMap::from([
//             ("BAD_KEY".into(), "should_not_be_used".into()),
//             ("MPC_ACCOUNT_ID".into(), "safe".into()),
//         ]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         assert!(!cmd.join(" ").contains("should_not_be_used"));
//         assert!(cmd.contains(&"MPC_ACCOUNT_ID=safe".to_string()));
//     }

//     #[test]
//     fn test_mpc_backup_encryption_key_is_allowed() {
//         let env = BTreeMap::from([("MPC_BACKUP_ENCRYPTION_KEY_HEX".into(), "0".repeat(64))]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         assert!(
//             cmd.join(" ")
//                 .contains(&format!("MPC_BACKUP_ENCRYPTION_KEY_HEX={}", "0".repeat(64)))
//         );
//     }

//     #[test]
//     fn test_malformed_extra_host_is_ignored() {
//         let env = BTreeMap::from([
//             (
//                 "EXTRA_HOSTS".into(),
//                 "badhostentry,no-colon,also--bad".into(),
//             ),
//             ("MPC_ACCOUNT_ID".into(), "safe".into()),
//         ]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         assert!(!cmd.contains(&"--add-host".to_string()));
//     }

//     #[test]
//     fn test_env_value_with_shell_injection_is_handled_safely() {
//         let env = BTreeMap::from([("MPC_ACCOUNT_ID".into(), "safe; rm -rf /".into())]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         assert!(cmd.contains(&"MPC_ACCOUNT_ID=safe; rm -rf /".to_string()));
//     }

//     #[test]
//     fn test_build_docker_cmd_nontee_no_dstack_mount() {
//         let mut env = BTreeMap::new();
//         env.insert("MPC_ACCOUNT_ID".into(), "x".into());
//         let cmd = build_docker_cmd(Platform::NonTee, &env, &make_digest()).unwrap();
//         let s = cmd.join(" ");
//         assert!(!s.contains("DSTACK_ENDPOINT="));
//         assert!(!s.contains(&format!("{DSTACK_UNIX_SOCKET}:{DSTACK_UNIX_SOCKET}")));
//     }

//     #[test]
//     fn test_build_docker_cmd_tee_has_dstack_mount() {
//         let env = BTreeMap::from([("MPC_ACCOUNT_ID".into(), "x".into())]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         let s = cmd.join(" ");
//         assert!(s.contains(&format!("DSTACK_ENDPOINT={DSTACK_UNIX_SOCKET}")));
//         assert!(s.contains(&format!("{DSTACK_UNIX_SOCKET}:{DSTACK_UNIX_SOCKET}")));
//     }

//     #[test]
//     fn test_build_docker_cmd_allows_arbitrary_mpc_prefix_env_vars() {
//         let mut env = base_env();
//         env.insert("MPC_NEW_FEATURE_FLAG".into(), "1".into());
//         env.insert("MPC_SOME_CONFIG".into(), "value".into());
//         let cmd = build_docker_cmd(Platform::NonTee, &env, &make_digest()).unwrap();
//         let cmd_str = cmd.join(" ");
//         assert!(cmd_str.contains("MPC_NEW_FEATURE_FLAG=1"));
//         assert!(cmd_str.contains("MPC_SOME_CONFIG=value"));
//     }

//     #[test]
//     fn test_build_docker_cmd_blocks_sensitive_mpc_private_keys() {
//         let mut env = base_env();
//         env.insert("MPC_P2P_PRIVATE_KEY".into(), "supersecret".into());
//         env.insert("MPC_ACCOUNT_SK".into(), "supersecret2".into());
//         let cmd = build_docker_cmd(Platform::NonTee, &env, &make_digest()).unwrap();
//         let cmd_str = cmd.join(" ");
//         assert!(!cmd_str.contains("MPC_P2P_PRIVATE_KEY"));
//         assert!(!cmd_str.contains("MPC_ACCOUNT_SK"));
//     }

//     #[test]
//     fn test_build_docker_cmd_rejects_env_value_with_newline() {
//         let mut env = base_env();
//         env.insert("MPC_NEW_FEATURE_FLAG".into(), "ok\nbad".into());
//         let cmd = build_docker_cmd(Platform::NonTee, &env, &make_digest()).unwrap();
//         let cmd_str = cmd.join(" ");
//         assert!(!cmd_str.contains("MPC_NEW_FEATURE_FLAG"));
//     }

//     #[test]
//     fn test_build_docker_cmd_enforces_max_env_count_cap() {
//         let mut env = base_env();
//         for i in 0..=MAX_PASSTHROUGH_ENV_VARS {
//             env.insert(format!("MPC_X_{i}"), "1".into());
//         }
//         let result = build_docker_cmd(Platform::NonTee, &env, &make_digest());
//         assert_matches!(result, Err(LauncherError::TooManyEnvVars(_)));
//     }

//     #[test]
//     fn test_build_docker_cmd_enforces_total_env_bytes_cap() {
//         let mut env = base_env();
//         for i in 0..40 {
//             env.insert(format!("MPC_BIG_{i}"), "a".repeat(MAX_ENV_VALUE_LEN));
//         }
//         let result = build_docker_cmd(Platform::NonTee, &env, &make_digest());
//         assert_matches!(result, Err(LauncherError::EnvPayloadTooLarge(_)));
//     }

//     // -- LD_PRELOAD injection tests -----------------------------------------

//     #[test]
//     fn test_ld_preload_injection_blocked_via_env_key() {
//         let env = BTreeMap::from([
//             ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
//             ("--env LD_PRELOAD".into(), "/path/to/my/malloc.so".into()),
//         ]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
//     }

//     #[test]
//     fn test_ld_preload_injection_blocked_via_extra_hosts() {
//         let env = BTreeMap::from([
//             ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
//             (
//                 "EXTRA_HOSTS".into(),
//                 "host1:192.168.0.1,host2:192.168.0.2,--env LD_PRELOAD=/path/to/my/malloc.so".into(),
//             ),
//         ]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         assert!(cmd.contains(&"--add-host".to_string()));
//         assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
//     }

//     #[test]
//     fn test_ld_preload_injection_blocked_via_ports() {
//         let env = BTreeMap::from([
//             ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
//             (
//                 "PORTS".into(),
//                 "11780:11780,--env LD_PRELOAD=/path/to/my/malloc.so".into(),
//             ),
//         ]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         assert!(cmd.contains(&"-p".to_string()));
//         assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
//     }

//     #[test]
//     fn test_ld_preload_injection_blocked_via_mpc_account_id() {
//         let env = BTreeMap::from([
//             (
//                 "MPC_ACCOUNT_ID".into(),
//                 "mpc-user-123, --env LD_PRELOAD=/path/to/my/malloc.so".into(),
//             ),
//             (
//                 "EXTRA_HOSTS".into(),
//                 "host1:192.168.0.1,host2:192.168.0.2".into(),
//             ),
//         ]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
//     }

//     #[test]
//     fn test_ld_preload_injection_blocked_via_dash_e() {
//         let env = BTreeMap::from([
//             ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
//             ("-e LD_PRELOAD".into(), "/path/to/my/malloc.so".into()),
//         ]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
//     }

//     #[test]
//     fn test_ld_preload_injection_blocked_via_extra_hosts_dash_e() {
//         let env = BTreeMap::from([
//             ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
//             (
//                 "EXTRA_HOSTS".into(),
//                 "host1:192.168.0.1,host2:192.168.0.2,-e LD_PRELOAD=/path/to/my/malloc.so".into(),
//             ),
//         ]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         assert!(cmd.contains(&"--add-host".to_string()));
//         assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
//     }

//     #[test]
//     fn test_ld_preload_injection_blocked_via_ports_dash_e() {
//         let env = BTreeMap::from([
//             ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
//             (
//                 "PORTS".into(),
//                 "11780:11780,-e LD_PRELOAD=/path/to/my/malloc.so".into(),
//             ),
//         ]);
//         let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
//         assert!(cmd.contains(&"-p".to_string()));
//         assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
//     }

//     // -- Hash selection tests -----------------------------------------------

//     fn make_digest_json(hashes: &[&str]) -> String {
//         serde_json::json!({"approved_hashes": hashes}).to_string()
//     }

//     #[test]
//     fn test_override_present() {
//         let dir = tempfile::tempdir().unwrap();
//         let file = dir.path().join("image-digest.bin");
//         let override_value = format!("sha256:{}", "a".repeat(64));
//         let approved = vec![
//             format!("sha256:{}", "b".repeat(64)),
//             override_value.clone(),
//             format!("sha256:{}", "c".repeat(64)),
//         ];
//         let json = serde_json::json!({"approved_hashes": approved}).to_string();
//         std::fs::write(&file, &json).unwrap();

//         // We can't easily override IMAGE_DIGEST_FILE constant, so test load_and_select_hash
//         // by creating a standalone test that reads from a custom path.
//         // Instead test the core logic directly:
//         let data: ApprovedHashesFile = serde_json::from_str(&json).unwrap();
//         assert!(data.approved_hashes.contains(&override_value));

//         // The override is in the approved list, so it should be valid
//         assert!(is_valid_sha256_digest(&override_value));
//         assert!(data.approved_hashes.contains(&override_value));
//     }

//     #[test]
//     fn test_override_not_in_list() {
//         let approved = vec!["sha256:aaa", "sha256:bbb"];
//         let json = make_digest_json(&approved);
//         let data: ApprovedHashesFile = serde_json::from_str(&json).unwrap();
//         let override_hash = "sha256:xyz";
//         assert!(!data.approved_hashes.contains(&override_hash.to_string()));
//     }

//     #[test]
//     fn test_no_override_picks_newest() {
//         let approved = vec!["sha256:newest", "sha256:older", "sha256:oldest"];
//         let json = make_digest_json(&approved);
//         let data: ApprovedHashesFile = serde_json::from_str(&json).unwrap();
//         assert_eq!(data.approved_hashes[0], "sha256:newest");
//     }

//     #[test]
//     fn test_json_key_matches_node() {
//         // Must stay aligned with crates/node/src/tee/allowed_image_hashes_watcher.rs
//         let json = r#"{"approved_hashes": ["sha256:abc"]}"#;
//         let data: ApprovedHashesFile = serde_json::from_str(json).unwrap();
//         assert_eq!(data.approved_hashes.len(), 1);
//     }

//     #[test]
//     fn test_get_bare_digest() {
//         assert_eq!(
//             get_bare_digest(&format!("sha256:{}", "a".repeat(64))).unwrap(),
//             "a".repeat(64)
//         );
//         get_bare_digest("invalid").unwrap_err();
//     }

//     #[test]
//     fn test_is_valid_sha256_digest() {
//         assert!(is_valid_sha256_digest(&format!(
//             "sha256:{}",
//             "a".repeat(64)
//         )));
//         assert!(!is_valid_sha256_digest("sha256:tooshort"));
//         assert!(!is_valid_sha256_digest("not-a-digest"));
//         // hex::decode accepts uppercase; as_hex() normalizes to lowercase
//         assert!(is_valid_sha256_digest(&format!(
//             "sha256:{}",
//             "A".repeat(64)
//         )));
//     }

//     #[test]
//     fn test_parse_image_digest_normalizes_case() {
//         let upper = format!("sha256:{}", "AB".repeat(32));
//         let hash = parse_image_digest(&upper).unwrap();
//         assert_eq!(hash.as_hex(), "ab".repeat(32));
//     }

//     // -- Full flow docker cmd test ------------------------------------------

//     #[test]
//     fn test_parse_and_build_docker_cmd_full_flow() {
//         let dir = tempfile::tempdir().unwrap();
//         let file = dir.path().join("user_config");
//         std::fs::write(
//             &file,
//             "MPC_ACCOUNT_ID=test-user\nPORTS=11780:11780, --env BAD=oops\nEXTRA_HOSTS=host1:192.168.1.1, --volume /:/mnt\n",
//         )
//         .unwrap();
//         let config = parse_user_config(file.to_str().unwrap()).unwrap();
//         let cmd = build_docker_cmd(Platform::Tee, &config.passthrough_env, &make_digest()).unwrap();
//         let cmd_str = cmd.join(" ");

//         assert!(cmd_str.contains("MPC_ACCOUNT_ID=test-user"));
//         assert!(cmd_str.contains("11780:11780"));
//         assert!(cmd_str.contains("host1:192.168.1.1"));
//         assert!(!cmd_str.contains("BAD=oops"));
//         assert!(!cmd_str.contains("/:/mnt"));
//     }

//     #[test]
//     fn test_full_docker_cmd_structure() {
//         let env = BTreeMap::from([("MPC_ACCOUNT_ID".into(), "test-user".into())]);
//         let digest = make_digest();
//         let cmd = build_docker_cmd(Platform::NonTee, &env, &digest).unwrap();

//         // Check required subsequence
//         assert!(cmd.contains(&"docker".to_string()));
//         assert!(cmd.contains(&"run".to_string()));
//         assert!(cmd.contains(&"--security-opt".to_string()));
//         assert!(cmd.contains(&"no-new-privileges:true".to_string()));
//         assert!(cmd.contains(&"/tapp:/tapp:ro".to_string()));
//         assert!(cmd.contains(&"shared-volume:/mnt/shared".to_string()));
//         assert!(cmd.contains(&"mpc-data:/data".to_string()));
//         assert!(cmd.contains(&MPC_CONTAINER_NAME.to_string()));
//         assert!(cmd.contains(&"--detach".to_string()));
//         // Image digest should be the last argument
//         assert_eq!(cmd.last().unwrap(), &digest);
//     }

//     // -- Dstack tests -------------------------------------------------------

//     #[test]
//     fn test_extend_rtmr3_nontee_is_noop() {
//         // NonTee should return immediately without touching dstack
//         let rt = tokio::runtime::Runtime::new().unwrap();
//         rt.block_on(extend_rtmr3(Platform::NonTee, &make_digest()))
//             .unwrap();
//     }

//     #[test]
//     fn test_extend_rtmr3_tee_requires_socket() {
//         // TEE mode should fail when socket doesn't exist
//         let rt = tokio::runtime::Runtime::new().unwrap();
//         let result = rt.block_on(extend_rtmr3(Platform::Tee, &make_digest()));
//         assert_matches!(result, Err(LauncherError::DstackSocketMissing(_)));
//     }

//     // -- MpcDockerImageHash integration test --------------------------------

//     #[test]
//     fn test_mpc_docker_image_hash_from_bare_hex() {
//         let bare_hex = "a".repeat(64);
//         let hash: MpcDockerImageHash = bare_hex.parse().unwrap();
//         assert_eq!(hash.as_hex(), bare_hex);
//     }

//     // -- Integration test (feature-gated) -----------------------------------

//     #[cfg(feature = "integration-test")]
//     mod integration {
//         use super::*;

//         const TEST_DIGEST: &str =
//             "sha256:f2472280c437efc00fa25a030a24990ae16c4fbec0d74914e178473ce4d57372";

//         fn test_dstack_config() -> Config {
//             user_config_from_map(BTreeMap::from([
//                 (
//                     "MPC_IMAGE_TAGS".into(),
//                     "83b52da4e2270c688cdd30da04f6b9d3565f25bb".into(),
//                 ),
//                 ("MPC_IMAGE_NAME".into(), "nearone/testing".into()),
//                 ("MPC_REGISTRY".into(), "registry.hub.docker.com".into()),
//             ]))
//             .unwrap()
//         }

//         #[tokio::test]
//         async fn test_validate_image_hash_real_registry() {
//             let timing = RpcTimingConfig {
//                 request_timeout_secs: 10.0,
//                 request_interval_secs: 1.0,
//                 max_attempts: 20,
//             };
//             let result = validate_image_hash(TEST_DIGEST, &test_dstack_config(), &timing)
//                 .await
//                 .unwrap();
//             assert!(result, "validate_image_hash() failed for test image");
//         }
//     }
// }
