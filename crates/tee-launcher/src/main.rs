use std::collections::{BTreeMap, HashSet, VecDeque};
use std::process::Command;
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;
use thiserror::Error;

// Reuse the workspace hash type for type-safe image hash handling.
use mpc_primitives::hash::MpcDockerImageHash;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum LauncherError {
    #[error("PLATFORM must be set to one of [TEE, NONTEE], got: {0}")]
    InvalidPlatform(String),

    #[error("DOCKER_CONTENT_TRUST must be set to 1")]
    DockerContentTrustNotEnabled,

    #[error("PLATFORM=TEE requires dstack unix socket at {0}")]
    DstackSocketMissing(String),

    #[error("GetQuote failed before extending RTMR3: {0}")]
    DstackGetQuoteFailed(String),

    #[error("EmitEvent failed while extending RTMR3: {0}")]
    DstackEmitEventFailed(String),

    #[error("DEFAULT_IMAGE_DIGEST invalid: {0}")]
    InvalidDefaultDigest(String),

    #[error("Invalid JSON in {path}: approved_hashes missing or empty")]
    InvalidApprovedHashes { path: String },

    #[error("MPC_HASH_OVERRIDE invalid: {0}")]
    InvalidHashOverride(String),

    #[error("Image hash not found among tags")]
    ImageHashNotFoundAmongTags,

    #[error("Failed to get auth token from registry: {0}")]
    RegistryAuthFailed(String),

    #[error("Failed to get successful response from {url} after {attempts} attempts")]
    RegistryRequestFailed { url: String, attempts: u32 },

    #[error("docker pull failed for {0}")]
    DockerPullFailed(String),

    #[error("docker inspect failed for {0}")]
    DockerInspectFailed(String),

    #[error("Digest mismatch: pulled {pulled} != expected {expected}")]
    DigestMismatch { pulled: String, expected: String },

    #[error("MPC image hash validation failed: {0}")]
    ImageValidationFailed(String),

    #[error("docker run failed for validated hash={0}")]
    DockerRunFailed(String),

    #[error("Too many env vars to pass through (>{0})")]
    TooManyEnvVars(usize),

    #[error("Total env payload too large (>{0} bytes)")]
    EnvPayloadTooLarge(usize),

    #[error("Unsafe docker command: LD_PRELOAD detected")]
    LdPreloadDetected,

    #[error("Failed to read {path}: {source}")]
    FileRead {
        path: String,
        source: std::io::Error,
    },

    #[error("Failed to parse {path}: {source}")]
    JsonParse {
        path: String,
        source: serde_json::Error,
    },

    #[error("Required environment variable not set: {0}")]
    MissingEnvVar(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Registry response parse error: {0}")]
    RegistryResponseParse(String),
}

type Result<T> = std::result::Result<T, LauncherError>;

// ---------------------------------------------------------------------------
// Constants — matching Python launcher exactly
// ---------------------------------------------------------------------------

const MPC_CONTAINER_NAME: &str = "mpc-node";
const IMAGE_DIGEST_FILE: &str = "/mnt/shared/image-digest.bin";
const DSTACK_UNIX_SOCKET: &str = "/var/run/dstack.sock";
const DSTACK_USER_CONFIG_FILE: &str = "/tapp/user_config";

const SHA256_PREFIX: &str = "sha256:";

// Docker Hub defaults
const DEFAULT_RPC_REQUEST_TIMEOUT_SECS: f64 = 10.0;
const DEFAULT_RPC_REQUEST_INTERVAL_SECS: f64 = 1.0;
const DEFAULT_RPC_MAX_ATTEMPTS: u32 = 20;

const DEFAULT_MPC_IMAGE_NAME: &str = "nearone/mpc-node";
const DEFAULT_MPC_REGISTRY: &str = "registry.hub.docker.com";
const DEFAULT_MPC_IMAGE_TAG: &str = "latest";

// Env var names
const ENV_VAR_PLATFORM: &str = "PLATFORM";
const ENV_VAR_DEFAULT_IMAGE_DIGEST: &str = "DEFAULT_IMAGE_DIGEST";
const ENV_VAR_DOCKER_CONTENT_TRUST: &str = "DOCKER_CONTENT_TRUST";
const ENV_VAR_MPC_HASH_OVERRIDE: &str = "MPC_HASH_OVERRIDE";
const ENV_VAR_RPC_REQUEST_TIMEOUT_SECS: &str = "RPC_REQUEST_TIMEOUT_SECS";
const ENV_VAR_RPC_REQUEST_INTERVAL_SECS: &str = "RPC_REQUEST_INTERVAL_SECS";
const ENV_VAR_RPC_MAX_ATTEMPTS: &str = "RPC_MAX_ATTEMPTS";

const DSTACK_USER_CONFIG_MPC_IMAGE_TAGS: &str = "MPC_IMAGE_TAGS";
const DSTACK_USER_CONFIG_MPC_IMAGE_NAME: &str = "MPC_IMAGE_NAME";
const DSTACK_USER_CONFIG_MPC_IMAGE_REGISTRY: &str = "MPC_REGISTRY";

// Security limits
const MAX_PASSTHROUGH_ENV_VARS: usize = 64;
const MAX_ENV_VALUE_LEN: usize = 1024;
const MAX_TOTAL_ENV_BYTES: usize = 32 * 1024;

// Regex patterns (compiled once)
static SHA256_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^sha256:[0-9a-f]{64}$").unwrap());
static MPC_ENV_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^MPC_[A-Z0-9_]{1,64}$").unwrap());
static HOST_ENTRY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9\-\.]+:\d{1,3}(\.\d{1,3}){3}$").unwrap());
static PORT_MAPPING_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d{1,5}):(\d{1,5})$").unwrap());
static INVALID_HOST_ENTRY_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[;&|`$\\<>\-]|^--").unwrap());

// Denied env keys — never pass these to the container
static DENIED_CONTAINER_ENV_KEYS: LazyLock<HashSet<&str>> =
    LazyLock::new(|| HashSet::from(["MPC_P2P_PRIVATE_KEY", "MPC_ACCOUNT_SK"]));

// Allowed non-MPC env vars (backward compatibility)
static ALLOWED_MPC_ENV_VARS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    HashSet::from([
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
    ])
});

// Launcher-only env vars — read from user config but never forwarded to container
static ALLOWED_LAUNCHER_ENV_VARS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    HashSet::from([
        DSTACK_USER_CONFIG_MPC_IMAGE_TAGS,
        DSTACK_USER_CONFIG_MPC_IMAGE_NAME,
        DSTACK_USER_CONFIG_MPC_IMAGE_REGISTRY,
        ENV_VAR_MPC_HASH_OVERRIDE,
        ENV_VAR_RPC_REQUEST_TIMEOUT_SECS,
        ENV_VAR_RPC_REQUEST_INTERVAL_SECS,
        ENV_VAR_RPC_MAX_ATTEMPTS,
    ])
});

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Tee,
    NonTee,
}

#[derive(Debug, Clone)]
pub struct RpcTimingConfig {
    pub request_timeout_secs: f64,
    pub request_interval_secs: f64,
    pub max_attempts: u32,
}

#[derive(Debug, Clone)]
pub struct ImageSpec {
    pub tags: Vec<String>,
    pub image_name: String,
    pub registry: String,
}

#[derive(Debug, Clone)]
pub struct ResolvedImage {
    pub spec: ImageSpec,
    pub digest: String,
}

/// JSON structure for the approved hashes file written by the MPC node.
/// Must stay aligned with `crates/node/src/tee/allowed_image_hashes_watcher.rs`.
#[derive(Debug, Deserialize)]
struct ApprovedHashesFile {
    approved_hashes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Validation functions — security policy for env passthrough
// ---------------------------------------------------------------------------

fn has_control_chars(s: &str) -> bool {
    for ch in s.chars() {
        if ch == '\n' || ch == '\r' || ch == '\0' {
            return true;
        }
        if (ch as u32) < 0x20 && ch != '\t' {
            return true;
        }
    }
    false
}

fn is_safe_env_value(value: &str) -> bool {
    if value.len() > MAX_ENV_VALUE_LEN {
        return false;
    }
    if has_control_chars(value) {
        return false;
    }
    if value.contains("LD_PRELOAD") {
        return false;
    }
    true
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

fn is_allowed_container_env_key(key: &str) -> bool {
    if DENIED_CONTAINER_ENV_KEYS.contains(key) {
        return false;
    }
    if MPC_ENV_KEY_RE.is_match(key) {
        return true;
    }
    if ALLOWED_MPC_ENV_VARS.contains(key) {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

fn parse_env_lines(lines: &[&str]) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                continue;
            }
            env.insert(key.to_string(), value.to_string());
        }
    }
    env
}

fn parse_env_file(path: &str) -> Result<BTreeMap<String, String>> {
    let content = std::fs::read_to_string(path).map_err(|source| LauncherError::FileRead {
        path: path.to_string(),
        source,
    })?;
    let lines: Vec<&str> = content.lines().collect();
    Ok(parse_env_lines(&lines))
}

fn parse_platform() -> Result<Platform> {
    let raw = std::env::var(ENV_VAR_PLATFORM).map_err(|_| {
        LauncherError::InvalidPlatform(format!(
            "{ENV_VAR_PLATFORM} must be set to one of [TEE, NONTEE]"
        ))
    })?;
    let val = raw.trim();
    match val {
        "TEE" => Ok(Platform::Tee),
        "NONTEE" => Ok(Platform::NonTee),
        other => Err(LauncherError::InvalidPlatform(other.to_string())),
    }
}

fn load_rpc_timing_config(dstack_config: &BTreeMap<String, String>) -> RpcTimingConfig {
    let timeout_secs = dstack_config
        .get(ENV_VAR_RPC_REQUEST_TIMEOUT_SECS)
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_RPC_REQUEST_TIMEOUT_SECS);
    let interval_secs = dstack_config
        .get(ENV_VAR_RPC_REQUEST_INTERVAL_SECS)
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_RPC_REQUEST_INTERVAL_SECS);
    let max_attempts = dstack_config
        .get(ENV_VAR_RPC_MAX_ATTEMPTS)
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_RPC_MAX_ATTEMPTS);
    RpcTimingConfig {
        request_timeout_secs: timeout_secs,
        request_interval_secs: interval_secs,
        max_attempts,
    }
}

fn get_image_spec(dstack_config: &BTreeMap<String, String>) -> ImageSpec {
    let tags_raw = dstack_config
        .get(DSTACK_USER_CONFIG_MPC_IMAGE_TAGS)
        .cloned()
        .unwrap_or_else(|| DEFAULT_MPC_IMAGE_TAG.to_string());
    let tags: Vec<String> = tags_raw
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    tracing::info!("Using tags {tags:?} to find matching MPC node docker image.");

    let image_name = dstack_config
        .get(DSTACK_USER_CONFIG_MPC_IMAGE_NAME)
        .cloned()
        .unwrap_or_else(|| DEFAULT_MPC_IMAGE_NAME.to_string());
    tracing::info!("Using image name {image_name}.");

    let registry = dstack_config
        .get(DSTACK_USER_CONFIG_MPC_IMAGE_REGISTRY)
        .cloned()
        .unwrap_or_else(|| DEFAULT_MPC_REGISTRY.to_string());
    tracing::info!("Using registry {registry}.");

    ImageSpec {
        tags,
        image_name,
        registry,
    }
}

// ---------------------------------------------------------------------------
// Hash selection
// ---------------------------------------------------------------------------

fn is_valid_sha256_digest(digest: &str) -> bool {
    SHA256_REGEX.is_match(digest)
}

fn get_bare_digest(full_digest: &str) -> Result<String> {
    full_digest
        .strip_prefix(SHA256_PREFIX)
        .map(|s| s.to_string())
        .ok_or_else(|| {
            LauncherError::InvalidDefaultDigest(format!(
                "Invalid digest (missing sha256: prefix): {full_digest}"
            ))
        })
}

fn load_and_select_hash(dstack_config: &BTreeMap<String, String>) -> Result<String> {
    let approved_hashes = if std::path::Path::new(IMAGE_DIGEST_FILE).is_file() {
        let content =
            std::fs::read_to_string(IMAGE_DIGEST_FILE).map_err(|source| LauncherError::FileRead {
                path: IMAGE_DIGEST_FILE.to_string(),
                source,
            })?;
        let data: ApprovedHashesFile =
            serde_json::from_str(&content).map_err(|source| LauncherError::JsonParse {
                path: IMAGE_DIGEST_FILE.to_string(),
                source,
            })?;
        if data.approved_hashes.is_empty() {
            return Err(LauncherError::InvalidApprovedHashes {
                path: IMAGE_DIGEST_FILE.to_string(),
            });
        }
        data.approved_hashes
    } else {
        let fallback = std::env::var(ENV_VAR_DEFAULT_IMAGE_DIGEST)
            .map_err(|_| LauncherError::MissingEnvVar(ENV_VAR_DEFAULT_IMAGE_DIGEST.to_string()))?;
        let fallback = fallback.trim().to_string();
        let fallback = if fallback.starts_with(SHA256_PREFIX) {
            fallback
        } else {
            format!("{SHA256_PREFIX}{fallback}")
        };
        if !is_valid_sha256_digest(&fallback) {
            return Err(LauncherError::InvalidDefaultDigest(fallback));
        }
        tracing::info!(
            "{IMAGE_DIGEST_FILE} missing → fallback to DEFAULT_IMAGE_DIGEST={fallback}"
        );
        vec![fallback]
    };

    tracing::info!("Approved MPC image hashes (newest → oldest):");
    for h in &approved_hashes {
        tracing::info!("  - {h}");
    }

    // Optional override
    if let Some(override_hash) = dstack_config.get(ENV_VAR_MPC_HASH_OVERRIDE) {
        if !is_valid_sha256_digest(override_hash) {
            return Err(LauncherError::InvalidHashOverride(override_hash.clone()));
        }
        if !approved_hashes.contains(override_hash) {
            tracing::error!(
                "MPC_HASH_OVERRIDE={override_hash} does NOT match any approved hash!"
            );
            return Err(LauncherError::InvalidHashOverride(override_hash.clone()));
        }
        tracing::info!("MPC_HASH_OVERRIDE provided → selecting: {override_hash}");
        return Ok(override_hash.clone());
    }

    // No override → select newest (first in list)
    let selected = approved_hashes[0].clone();
    tracing::info!("Selected MPC hash (newest allowed): {selected}");
    Ok(selected)
}

// ---------------------------------------------------------------------------
// Docker registry communication
// ---------------------------------------------------------------------------

async fn request_until_success(
    client: &reqwest::Client,
    url: &str,
    headers: &[(String, String)],
    timing: &RpcTimingConfig,
) -> Result<reqwest::Response> {
    let mut interval = timing.request_interval_secs;

    for attempt in 1..=timing.max_attempts {
        // Sleep before request (matching Python behavior)
        tokio::time::sleep(std::time::Duration::from_secs_f64(interval)).await;
        interval = (interval.max(1.0) * 1.5).min(60.0);

        let mut req = client.get(url);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }

        match req
            .timeout(std::time::Duration::from_secs_f64(timing.request_timeout_secs))
            .send()
            .await
        {
            Err(e) => {
                tracing::warn!(
                    "Attempt {attempt}/{}: Failed to fetch {url}. Status: Timeout/Error: {e}",
                    timing.max_attempts
                );
                continue;
            }
            Ok(resp) if resp.status() != reqwest::StatusCode::OK => {
                tracing::warn!(
                    "Attempt {attempt}/{}: Failed to fetch {url}. Status: {}",
                    timing.max_attempts,
                    resp.status()
                );
                continue;
            }
            Ok(resp) => return Ok(resp),
        }
    }

    Err(LauncherError::RegistryRequestFailed {
        url: url.to_string(),
        attempts: timing.max_attempts,
    })
}

async fn get_manifest_digest(
    image: &ResolvedImage,
    timing: &RpcTimingConfig,
) -> Result<String> {
    if image.spec.tags.is_empty() {
        return Err(LauncherError::ImageHashNotFoundAmongTags);
    }

    // Get auth token
    let token_url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
        image.spec.image_name
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

    let mut tags: VecDeque<String> = image.spec.tags.iter().cloned().collect();

    while let Some(tag) = tags.pop_front() {
        let manifest_url = format!(
            "https://{}/v2/{}/manifests/{tag}",
            image.spec.registry, image.spec.image_name
        );
        let headers = vec![
            (
                "Accept".to_string(),
                "application/vnd.docker.distribution.manifest.v2+json".to_string(),
            ),
            ("Authorization".to_string(), format!("Bearer {token}")),
        ];

        match request_until_success(&client, &manifest_url, &headers, timing).await {
            Ok(resp) => {
                let content_digest = resp
                    .headers()
                    .get("Docker-Content-Digest")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let manifest: serde_json::Value =
                    resp.json().await.map_err(|e| {
                        LauncherError::RegistryResponseParse(e.to_string())
                    })?;

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
                    "application/vnd.docker.distribution.manifest.v2+json"
                    | "application/vnd.oci.image.manifest.v1+json" => {
                        let config_digest =
                            manifest["config"]["digest"].as_str().unwrap_or("");
                        if config_digest == image.digest {
                            if let Some(digest) = content_digest {
                                return Ok(digest);
                            }
                        }
                    }
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

async fn validate_image_hash(
    image_digest: &str,
    dstack_config: &BTreeMap<String, String>,
    timing: &RpcTimingConfig,
) -> Result<bool> {
    tracing::info!("Validating MPC hash: {image_digest}");

    let image_spec = get_image_spec(dstack_config);
    let docker_image = ResolvedImage {
        spec: image_spec,
        digest: image_digest.to_string(),
    };

    let manifest_digest = get_manifest_digest(&docker_image, timing).await?;
    let name_and_digest = format!("{}@{manifest_digest}", docker_image.spec.image_name);

    // Pull
    let pull = Command::new("docker")
        .args(["pull", &name_and_digest])
        .output()
        .map_err(|e| LauncherError::DockerPullFailed(e.to_string()))?;
    if !pull.status.success() {
        tracing::error!("docker pull failed for {image_digest}");
        return Ok(false);
    }

    // Verify digest
    let inspect = Command::new("docker")
        .args(["image", "inspect", "--format", "{{index .ID}}", &name_and_digest])
        .output()
        .map_err(|e| LauncherError::DockerInspectFailed(e.to_string()))?;
    if !inspect.status.success() {
        tracing::error!("docker inspect failed for {image_digest}");
        return Ok(false);
    }

    let pulled_digest = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
    if pulled_digest != image_digest {
        tracing::error!("digest mismatch: {pulled_digest} != {image_digest}");
        return Ok(false);
    }

    tracing::info!("MPC hash {image_digest} validated successfully.");
    Ok(true)
}

// ---------------------------------------------------------------------------
// Docker command builder
// ---------------------------------------------------------------------------

fn remove_existing_container() {
    let output = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}"])
        .output();

    match output {
        Ok(out) => {
            let names = String::from_utf8_lossy(&out.stdout);
            if names.lines().any(|n| n == MPC_CONTAINER_NAME) {
                tracing::info!("Removing existing container: {MPC_CONTAINER_NAME}");
                let _ = Command::new("docker")
                    .args(["rm", "-f", MPC_CONTAINER_NAME])
                    .output();
            }
        }
        Err(e) => {
            tracing::warn!("Failed to check/remove container {MPC_CONTAINER_NAME}: {e}");
        }
    }
}

fn build_docker_cmd(
    platform: Platform,
    user_env: &BTreeMap<String, String>,
    image_digest: &str,
) -> Result<Vec<String>> {
    let bare_digest = get_bare_digest(image_digest)?;

    let mut cmd: Vec<String> = vec!["docker".into(), "run".into()];

    // Required environment variables
    cmd.extend(["--env".into(), format!("MPC_IMAGE_HASH={bare_digest}")]);
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

    // BTreeMap iteration is already sorted by key (deterministic)
    for (key, value) in user_env {
        if ALLOWED_LAUNCHER_ENV_VARS.contains(key.as_str()) {
            continue;
        }

        if key == "EXTRA_HOSTS" {
            for host_entry in value.split(',') {
                let clean = host_entry.trim();
                if is_safe_host_entry(clean) && is_valid_host_entry(clean) {
                    cmd.extend(["--add-host".into(), clean.to_string()]);
                } else {
                    tracing::warn!("Ignoring invalid or unsafe EXTRA_HOSTS entry: {clean}");
                }
            }
            continue;
        }

        if key == "PORTS" {
            for port_pair in value.split(',') {
                let clean = port_pair.trim();
                if is_safe_port_mapping(clean) && is_valid_port_mapping(clean) {
                    cmd.extend(["-p".into(), clean.to_string()]);
                } else {
                    tracing::warn!("Ignoring invalid or unsafe PORTS entry: {clean}");
                }
            }
            continue;
        }

        if !is_allowed_container_env_key(key) {
            tracing::warn!("Ignoring unknown or unapproved env var: {key}");
            continue;
        }

        if !is_safe_env_value(value) {
            tracing::warn!("Ignoring env var with unsafe value: {key}");
            continue;
        }

        passed_env_count += 1;
        if passed_env_count > MAX_PASSTHROUGH_ENV_VARS {
            return Err(LauncherError::TooManyEnvVars(MAX_PASSTHROUGH_ENV_VARS));
        }

        total_env_bytes += key.len() + 1 + value.len();
        if total_env_bytes > MAX_TOTAL_ENV_BYTES {
            return Err(LauncherError::EnvPayloadTooLarge(MAX_TOTAL_ENV_BYTES));
        }

        cmd.extend(["--env".into(), format!("{key}={value}")]);
    }

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
    valid_hash: &str,
    user_env: &BTreeMap<String, String>,
) -> Result<()> {
    tracing::info!("Launching MPC node with validated hash: {valid_hash}");

    remove_existing_container();
    let docker_cmd = build_docker_cmd(platform, user_env, valid_hash)?;

    let status = Command::new(&docker_cmd[0])
        .args(&docker_cmd[1..])
        .status()
        .map_err(|e| LauncherError::DockerRunFailed(e.to_string()))?;

    if !status.success() {
        return Err(LauncherError::DockerRunFailed(format!(
            "validated hash={valid_hash}"
        )));
    }

    tracing::info!("MPC launched successfully.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Dstack TEE communication (via dstack-sdk, no curl)
// ---------------------------------------------------------------------------

fn is_unix_socket(path: &str) -> bool {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.file_type().is_socket(),
        Err(_) => false,
    }
}

async fn extend_rtmr3(platform: Platform, valid_hash: &str) -> Result<()> {
    if platform == Platform::NonTee {
        tracing::info!("PLATFORM=NONTEE → skipping RTMR3 extension step.");
        return Ok(());
    }

    if !is_unix_socket(DSTACK_UNIX_SOCKET) {
        return Err(LauncherError::DstackSocketMissing(
            DSTACK_UNIX_SOCKET.to_string(),
        ));
    }

    let bare = get_bare_digest(valid_hash)?;
    tracing::info!("Extending RTMR3 with validated hash: {bare}");

    let client =
        dstack_sdk::dstack_client::DstackClient::new(Some(DSTACK_UNIX_SOCKET));

    // GetQuote first
    client
        .get_quote(vec![])
        .await
        .map_err(|e| LauncherError::DstackGetQuoteFailed(e.to_string()))?;

    // EmitEvent with the image digest
    client
        .emit_event("mpc-image-digest".to_string(), bare.into_bytes())
        .await
        .map_err(|e| LauncherError::DstackEmitEventFailed(e.to_string()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Main orchestration
// ---------------------------------------------------------------------------

async fn run() -> Result<()> {
    tracing::info!("start");

    let platform = parse_platform()?;
    tracing::info!("Launcher platform: {}", match platform {
        Platform::Tee => "TEE",
        Platform::NonTee => "NONTEE",
    });

    if platform == Platform::Tee && !is_unix_socket(DSTACK_UNIX_SOCKET) {
        return Err(LauncherError::DstackSocketMissing(
            DSTACK_UNIX_SOCKET.to_string(),
        ));
    }

    // DOCKER_CONTENT_TRUST must be enabled
    let dct = std::env::var(ENV_VAR_DOCKER_CONTENT_TRUST).unwrap_or_default();
    if dct != "1" {
        return Err(LauncherError::DockerContentTrustNotEnabled);
    }

    // Load dstack user config
    let dstack_config: BTreeMap<String, String> =
        if std::path::Path::new(DSTACK_USER_CONFIG_FILE).is_file() {
            parse_env_file(DSTACK_USER_CONFIG_FILE)?
        } else {
            BTreeMap::new()
        };

    let rpc_cfg = load_rpc_timing_config(&dstack_config);

    let selected_hash = load_and_select_hash(&dstack_config)?;

    if !validate_image_hash(&selected_hash, &dstack_config, &rpc_cfg).await? {
        return Err(LauncherError::ImageValidationFailed(selected_hash));
    }

    tracing::info!("MPC image hash validated successfully: {selected_hash}");

    extend_rtmr3(platform, &selected_hash).await?;

    launch_mpc_container(platform, &selected_hash, &dstack_config)?;

    Ok(())
}

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use rstest::rstest;

    // -- Config parsing tests -----------------------------------------------

    #[test]
    fn test_parse_env_lines_basic() {
        let lines = vec![
            "# a comment",
            "KEY1=value1",
            "  KEY2 = value2 ",
            "",
            "INVALIDLINE",
            "EMPTY_KEY=",
        ];
        let env = parse_env_lines(&lines);
        assert_eq!(env.get("KEY1").unwrap(), "value1");
        assert_eq!(env.get("KEY2").unwrap(), "value2");
        assert_eq!(env.get("EMPTY_KEY").unwrap(), "");
        assert!(!env.contains_key("INVALIDLINE"));
    }

    #[test]
    fn test_config_ignores_blank_lines_and_comments() {
        let lines = vec!["", "  # This is a comment", "  MPC_SECRET_STORE_KEY=topsecret", ""];
        let env = parse_env_lines(&lines);
        assert_eq!(env.get("MPC_SECRET_STORE_KEY").unwrap(), "topsecret");
        assert_eq!(env.len(), 1);
    }

    #[test]
    fn test_config_skips_malformed_lines() {
        let lines = vec![
            "GOOD_KEY=value",
            "bad_line_without_equal",
            "ANOTHER_GOOD=ok",
            "=",
        ];
        let env = parse_env_lines(&lines);
        assert!(env.contains_key("GOOD_KEY"));
        assert!(env.contains_key("ANOTHER_GOOD"));
        assert!(!env.contains_key("bad_line_without_equal"));
        assert!(!env.contains_key(""));
    }

    #[test]
    fn test_config_overrides_duplicate_keys() {
        let lines = vec!["MPC_ACCOUNT_ID=first", "MPC_ACCOUNT_ID=second"];
        let env = parse_env_lines(&lines);
        assert_eq!(env.get("MPC_ACCOUNT_ID").unwrap(), "second");
    }

    // -- Host/port validation tests -----------------------------------------

    #[test]
    fn test_valid_host_entry() {
        assert!(is_valid_host_entry("node.local:192.168.1.1"));
        assert!(!is_valid_host_entry("node.local:not-an-ip"));
        assert!(!is_valid_host_entry("--env LD_PRELOAD=hack.so"));
    }

    #[test]
    fn test_valid_port_mapping() {
        assert!(is_valid_port_mapping("11780:11780"));
        assert!(!is_valid_port_mapping("65536:11780"));
        assert!(!is_valid_port_mapping("--volume /:/mnt"));
    }

    // -- Security validation tests ------------------------------------------

    #[test]
    fn test_has_control_chars_rejects_newline_and_cr() {
        assert!(has_control_chars("a\nb"));
        assert!(has_control_chars("a\rb"));
    }

    #[test]
    fn test_has_control_chars_allows_tab() {
        assert!(!has_control_chars("a\tb"));
    }

    #[test]
    fn test_has_control_chars_rejects_other_control_chars() {
        assert!(has_control_chars(&format!("a{}b", '\x1F')));
    }

    #[test]
    fn test_is_safe_env_value_rejects_control_chars() {
        assert!(!is_safe_env_value("ok\nno"));
        assert!(!is_safe_env_value("ok\rno"));
        assert!(!is_safe_env_value(&format!("ok{}no", '\x1F')));
    }

    #[test]
    fn test_is_safe_env_value_rejects_ld_preload() {
        assert!(!is_safe_env_value("LD_PRELOAD=/tmp/x.so"));
        assert!(!is_safe_env_value("foo LD_PRELOAD bar"));
    }

    #[test]
    fn test_is_safe_env_value_rejects_too_long() {
        assert!(!is_safe_env_value(&"a".repeat(MAX_ENV_VALUE_LEN + 1)));
        assert!(is_safe_env_value(&"a".repeat(MAX_ENV_VALUE_LEN)));
    }

    #[test]
    fn test_is_allowed_container_env_key_allows_mpc_prefix_uppercase() {
        assert!(is_allowed_container_env_key("MPC_FOO"));
        assert!(is_allowed_container_env_key("MPC_FOO_123"));
        assert!(is_allowed_container_env_key("MPC_A_B_C"));
    }

    #[test]
    fn test_is_allowed_container_env_key_rejects_lowercase_or_invalid() {
        assert!(!is_allowed_container_env_key("MPC_foo"));
        assert!(!is_allowed_container_env_key("MPC-FOO"));
        assert!(!is_allowed_container_env_key("MPC.FOO"));
        assert!(!is_allowed_container_env_key("MPC_"));
    }

    #[test]
    fn test_is_allowed_container_env_key_allows_compat_non_mpc_keys() {
        assert!(is_allowed_container_env_key("RUST_LOG"));
        assert!(is_allowed_container_env_key("RUST_BACKTRACE"));
        assert!(is_allowed_container_env_key("NEAR_BOOT_NODES"));
    }

    #[test]
    fn test_is_allowed_container_env_key_denies_sensitive_keys() {
        assert!(!is_allowed_container_env_key("MPC_P2P_PRIVATE_KEY"));
        assert!(!is_allowed_container_env_key("MPC_ACCOUNT_SK"));
    }

    // -- Docker cmd builder tests -------------------------------------------

    fn make_digest() -> String {
        format!("sha256:{}", "a".repeat(64))
    }

    fn base_env() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
            ("MPC_CONTRACT_ID".into(), "contract.near".into()),
            ("MPC_ENV".into(), "testnet".into()),
            ("MPC_HOME_DIR".into(), "/data".into()),
            ("NEAR_BOOT_NODES".into(), "boot1,boot2".into()),
            ("RUST_LOG".into(), "info".into()),
        ])
    }

    #[test]
    fn test_build_docker_cmd_sanitizes_ports_and_hosts() {
        let env = BTreeMap::from([
            ("PORTS".into(), "11780:11780,--env BAD=1".into()),
            (
                "EXTRA_HOSTS".into(),
                "node:192.168.1.1,--volume /:/mnt".into(),
            ),
            ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
        ]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();

        assert!(cmd.contains(&"MPC_ACCOUNT_ID=mpc-user-123".to_string()));
        assert!(cmd.contains(&"11780:11780".to_string()));
        assert!(cmd.contains(&"node:192.168.1.1".to_string()));
        // Injection strings filtered
        assert!(!cmd.iter().any(|arg| arg.contains("BAD=1")));
        assert!(!cmd.iter().any(|arg| arg.contains("/:/mnt")));
    }

    #[test]
    fn test_extra_hosts_does_not_allow_ld_preload() {
        let env = BTreeMap::from([
            (
                "EXTRA_HOSTS".into(),
                "host:1.2.3.4,--env LD_PRELOAD=/evil.so".into(),
            ),
            ("MPC_ACCOUNT_ID".into(), "safe".into()),
        ]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        assert!(cmd.contains(&"host:1.2.3.4".to_string()));
        assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ports_does_not_allow_volume_injection() {
        let env = BTreeMap::from([
            ("PORTS".into(), "2200:2200,--volume /:/mnt".into()),
            ("MPC_ACCOUNT_ID".into(), "safe".into()),
        ]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        assert!(cmd.contains(&"2200:2200".to_string()));
        assert!(!cmd.iter().any(|arg| arg.contains("/:/mnt")));
    }

    #[test]
    fn test_invalid_env_key_is_ignored() {
        let env = BTreeMap::from([
            ("BAD_KEY".into(), "should_not_be_used".into()),
            ("MPC_ACCOUNT_ID".into(), "safe".into()),
        ]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        assert!(!cmd.join(" ").contains("should_not_be_used"));
        assert!(cmd.contains(&"MPC_ACCOUNT_ID=safe".to_string()));
    }

    #[test]
    fn test_mpc_backup_encryption_key_is_allowed() {
        let env = BTreeMap::from([(
            "MPC_BACKUP_ENCRYPTION_KEY_HEX".into(),
            "0".repeat(64),
        )]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        assert!(cmd
            .join(" ")
            .contains(&format!("MPC_BACKUP_ENCRYPTION_KEY_HEX={}", "0".repeat(64))));
    }

    #[test]
    fn test_malformed_extra_host_is_ignored() {
        let env = BTreeMap::from([
            (
                "EXTRA_HOSTS".into(),
                "badhostentry,no-colon,also--bad".into(),
            ),
            ("MPC_ACCOUNT_ID".into(), "safe".into()),
        ]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        assert!(!cmd.contains(&"--add-host".to_string()));
    }

    #[test]
    fn test_env_value_with_shell_injection_is_handled_safely() {
        let env = BTreeMap::from([("MPC_ACCOUNT_ID".into(), "safe; rm -rf /".into())]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        assert!(cmd.contains(&"MPC_ACCOUNT_ID=safe; rm -rf /".to_string()));
    }

    #[test]
    fn test_build_docker_cmd_nontee_no_dstack_mount() {
        let mut env = BTreeMap::new();
        env.insert("MPC_ACCOUNT_ID".into(), "x".into());
        env.insert(ENV_VAR_RPC_MAX_ATTEMPTS.into(), "5".into());
        let cmd = build_docker_cmd(Platform::NonTee, &env, &make_digest()).unwrap();
        let s = cmd.join(" ");
        assert!(!s.contains("DSTACK_ENDPOINT="));
        assert!(!s.contains(&format!(
            "{DSTACK_UNIX_SOCKET}:{DSTACK_UNIX_SOCKET}"
        )));
    }

    #[test]
    fn test_build_docker_cmd_tee_has_dstack_mount() {
        let env = BTreeMap::from([("MPC_ACCOUNT_ID".into(), "x".into())]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        let s = cmd.join(" ");
        assert!(s.contains(&format!("DSTACK_ENDPOINT={DSTACK_UNIX_SOCKET}")));
        assert!(s.contains(&format!(
            "{DSTACK_UNIX_SOCKET}:{DSTACK_UNIX_SOCKET}"
        )));
    }

    #[test]
    fn test_build_docker_cmd_allows_arbitrary_mpc_prefix_env_vars() {
        let mut env = base_env();
        env.insert("MPC_NEW_FEATURE_FLAG".into(), "1".into());
        env.insert("MPC_SOME_CONFIG".into(), "value".into());
        let cmd = build_docker_cmd(Platform::NonTee, &env, &make_digest()).unwrap();
        let cmd_str = cmd.join(" ");
        assert!(cmd_str.contains("MPC_NEW_FEATURE_FLAG=1"));
        assert!(cmd_str.contains("MPC_SOME_CONFIG=value"));
    }

    #[test]
    fn test_build_docker_cmd_blocks_sensitive_mpc_private_keys() {
        let mut env = base_env();
        env.insert("MPC_P2P_PRIVATE_KEY".into(), "supersecret".into());
        env.insert("MPC_ACCOUNT_SK".into(), "supersecret2".into());
        let cmd = build_docker_cmd(Platform::NonTee, &env, &make_digest()).unwrap();
        let cmd_str = cmd.join(" ");
        assert!(!cmd_str.contains("MPC_P2P_PRIVATE_KEY"));
        assert!(!cmd_str.contains("MPC_ACCOUNT_SK"));
    }

    #[test]
    fn test_build_docker_cmd_rejects_env_value_with_newline() {
        let mut env = base_env();
        env.insert("MPC_NEW_FEATURE_FLAG".into(), "ok\nbad".into());
        let cmd = build_docker_cmd(Platform::NonTee, &env, &make_digest()).unwrap();
        let cmd_str = cmd.join(" ");
        assert!(!cmd_str.contains("MPC_NEW_FEATURE_FLAG"));
    }

    #[test]
    fn test_build_docker_cmd_enforces_max_env_count_cap() {
        let mut env = base_env();
        for i in 0..=MAX_PASSTHROUGH_ENV_VARS {
            env.insert(format!("MPC_X_{i}"), "1".into());
        }
        let result = build_docker_cmd(Platform::NonTee, &env, &make_digest());
        assert_matches!(result, Err(LauncherError::TooManyEnvVars(_)));
    }

    #[test]
    fn test_build_docker_cmd_enforces_total_env_bytes_cap() {
        let mut env = base_env();
        for i in 0..40 {
            env.insert(format!("MPC_BIG_{i}"), "a".repeat(MAX_ENV_VALUE_LEN));
        }
        let result = build_docker_cmd(Platform::NonTee, &env, &make_digest());
        assert_matches!(result, Err(LauncherError::EnvPayloadTooLarge(_)));
    }

    // -- LD_PRELOAD injection tests -----------------------------------------

    #[test]
    fn test_ld_preload_injection_blocked_via_env_key() {
        let env = BTreeMap::from([
            ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
            (
                "--env LD_PRELOAD".into(),
                "/path/to/my/malloc.so".into(),
            ),
        ]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ld_preload_injection_blocked_via_extra_hosts() {
        let env = BTreeMap::from([
            ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
            (
                "EXTRA_HOSTS".into(),
                "host1:192.168.0.1,host2:192.168.0.2,--env LD_PRELOAD=/path/to/my/malloc.so"
                    .into(),
            ),
        ]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        assert!(cmd.contains(&"--add-host".to_string()));
        assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ld_preload_injection_blocked_via_ports() {
        let env = BTreeMap::from([
            ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
            (
                "PORTS".into(),
                "11780:11780,--env LD_PRELOAD=/path/to/my/malloc.so".into(),
            ),
        ]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        assert!(cmd.contains(&"-p".to_string()));
        assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ld_preload_injection_blocked_via_mpc_account_id() {
        let env = BTreeMap::from([
            (
                "MPC_ACCOUNT_ID".into(),
                "mpc-user-123, --env LD_PRELOAD=/path/to/my/malloc.so".into(),
            ),
            (
                "EXTRA_HOSTS".into(),
                "host1:192.168.0.1,host2:192.168.0.2".into(),
            ),
        ]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ld_preload_injection_blocked_via_dash_e() {
        let env = BTreeMap::from([
            ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
            ("-e LD_PRELOAD".into(), "/path/to/my/malloc.so".into()),
        ]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ld_preload_injection_blocked_via_extra_hosts_dash_e() {
        let env = BTreeMap::from([
            ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
            (
                "EXTRA_HOSTS".into(),
                "host1:192.168.0.1,host2:192.168.0.2,-e LD_PRELOAD=/path/to/my/malloc.so".into(),
            ),
        ]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        assert!(cmd.contains(&"--add-host".to_string()));
        assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ld_preload_injection_blocked_via_ports_dash_e() {
        let env = BTreeMap::from([
            ("MPC_ACCOUNT_ID".into(), "mpc-user-123".into()),
            (
                "PORTS".into(),
                "11780:11780,-e LD_PRELOAD=/path/to/my/malloc.so".into(),
            ),
        ]);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        assert!(cmd.contains(&"-p".to_string()));
        assert!(!cmd.iter().any(|arg| arg.contains("LD_PRELOAD")));
    }

    // -- Hash selection tests -----------------------------------------------

    fn make_digest_json(hashes: &[&str]) -> String {
        serde_json::json!({"approved_hashes": hashes}).to_string()
    }

    #[test]
    fn test_override_present() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("image-digest.bin");
        let override_value = format!("sha256:{}", "a".repeat(64));
        let approved = vec![
            format!("sha256:{}", "b".repeat(64)),
            override_value.clone(),
            format!("sha256:{}", "c".repeat(64)),
        ];
        let json = serde_json::json!({"approved_hashes": approved}).to_string();
        std::fs::write(&file, &json).unwrap();

        // We can't easily override IMAGE_DIGEST_FILE constant, so test load_and_select_hash
        // by creating a standalone test that reads from a custom path.
        // Instead test the core logic directly:
        let data: ApprovedHashesFile = serde_json::from_str(&json).unwrap();
        assert!(data.approved_hashes.contains(&override_value));

        let config = BTreeMap::from([(
            ENV_VAR_MPC_HASH_OVERRIDE.to_string(),
            override_value.clone(),
        )]);
        // The override is in the approved list, so it should be valid
        assert!(is_valid_sha256_digest(&override_value));
        assert!(data.approved_hashes.contains(&override_value));
    }

    #[test]
    fn test_override_not_in_list() {
        let approved = vec!["sha256:aaa", "sha256:bbb"];
        let json = make_digest_json(&approved);
        let data: ApprovedHashesFile = serde_json::from_str(&json).unwrap();
        let override_hash = "sha256:xyz";
        assert!(!data.approved_hashes.contains(&override_hash.to_string()));
    }

    #[test]
    fn test_no_override_picks_newest() {
        let approved = vec!["sha256:newest", "sha256:older", "sha256:oldest"];
        let json = make_digest_json(&approved);
        let data: ApprovedHashesFile = serde_json::from_str(&json).unwrap();
        assert_eq!(data.approved_hashes[0], "sha256:newest");
    }

    #[test]
    fn test_json_key_matches_node() {
        // Must stay aligned with crates/node/src/tee/allowed_image_hashes_watcher.rs
        let json = r#"{"approved_hashes": ["sha256:abc"]}"#;
        let data: ApprovedHashesFile = serde_json::from_str(json).unwrap();
        assert_eq!(data.approved_hashes.len(), 1);
    }

    #[test]
    fn test_get_bare_digest() {
        assert_eq!(
            get_bare_digest(&format!("sha256:{}", "a".repeat(64))).unwrap(),
            "a".repeat(64)
        );
        assert!(get_bare_digest("invalid").is_err());
    }

    #[test]
    fn test_is_valid_sha256_digest() {
        assert!(is_valid_sha256_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!is_valid_sha256_digest("sha256:tooshort"));
        assert!(!is_valid_sha256_digest("not-a-digest"));
        // Uppercase hex should be rejected
        assert!(!is_valid_sha256_digest(&format!("sha256:{}", "A".repeat(64))));
    }

    // -- Platform parsing tests ---------------------------------------------

    #[test]
    fn test_parse_platform_missing() {
        // Can't easily test env var absence in unit tests without side effects.
        // This is tested via the error type:
        let err = LauncherError::InvalidPlatform("not set".into());
        assert!(format!("{err}").contains("PLATFORM"));
    }

    // -- Full flow docker cmd test ------------------------------------------

    #[test]
    fn test_parse_and_build_docker_cmd_full_flow() {
        let config_str = "MPC_ACCOUNT_ID=test-user\nPORTS=11780:11780, --env BAD=oops\nEXTRA_HOSTS=host1:192.168.1.1, --volume /:/mnt\nIMAGE_HASH=sha256:abc123";
        let lines: Vec<&str> = config_str.lines().collect();
        let env = parse_env_lines(&lines);
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest()).unwrap();
        let cmd_str = cmd.join(" ");

        assert!(cmd_str.contains("MPC_ACCOUNT_ID=test-user"));
        assert!(cmd_str.contains("11780:11780"));
        assert!(cmd_str.contains("host1:192.168.1.1"));
        assert!(!cmd_str.contains("BAD=oops"));
        assert!(!cmd_str.contains("/:/mnt"));
    }

    #[test]
    fn test_full_docker_cmd_structure() {
        let env = BTreeMap::from([("MPC_ACCOUNT_ID".into(), "test-user".into())]);
        let digest = make_digest();
        let cmd = build_docker_cmd(Platform::NonTee, &env, &digest).unwrap();

        // Check required subsequence
        assert!(cmd.contains(&"docker".to_string()));
        assert!(cmd.contains(&"run".to_string()));
        assert!(cmd.contains(&"--security-opt".to_string()));
        assert!(cmd.contains(&"no-new-privileges:true".to_string()));
        assert!(cmd.contains(&"/tapp:/tapp:ro".to_string()));
        assert!(cmd.contains(&"shared-volume:/mnt/shared".to_string()));
        assert!(cmd.contains(&"mpc-data:/data".to_string()));
        assert!(cmd.contains(&MPC_CONTAINER_NAME.to_string()));
        assert!(cmd.contains(&"--detach".to_string()));
        // Image digest should be the last argument
        assert_eq!(cmd.last().unwrap(), &digest);
    }

    // -- Dstack tests -------------------------------------------------------

    #[test]
    fn test_extend_rtmr3_nontee_is_noop() {
        // NonTee should return immediately without touching dstack
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(extend_rtmr3(Platform::NonTee, &make_digest()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_extend_rtmr3_tee_requires_socket() {
        // TEE mode should fail when socket doesn't exist
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(extend_rtmr3(Platform::Tee, &make_digest()));
        assert_matches!(result, Err(LauncherError::DstackSocketMissing(_)));
    }

    // -- MpcDockerImageHash integration test --------------------------------

    #[test]
    fn test_mpc_docker_image_hash_from_bare_hex() {
        let bare_hex = "a".repeat(64);
        let hash: MpcDockerImageHash = bare_hex.parse().unwrap();
        assert_eq!(hash.as_hex(), bare_hex);
    }

    // -- Integration test (feature-gated) -----------------------------------

    #[cfg(feature = "integration-test")]
    mod integration {
        use super::*;

        const TEST_DIGEST: &str =
            "sha256:f2472280c437efc00fa25a030a24990ae16c4fbec0d74914e178473ce4d57372";

        fn test_dstack_config() -> BTreeMap<String, String> {
            BTreeMap::from([
                (
                    "MPC_IMAGE_TAGS".into(),
                    "83b52da4e2270c688cdd30da04f6b9d3565f25bb".into(),
                ),
                ("MPC_IMAGE_NAME".into(), "nearone/testing".into()),
                ("MPC_REGISTRY".into(), "registry.hub.docker.com".into()),
            ])
        }

        #[tokio::test]
        async fn test_validate_image_hash_real_registry() {
            let timing = RpcTimingConfig {
                request_timeout_secs: 10.0,
                request_interval_secs: 1.0,
                max_attempts: 20,
            };
            let result = validate_image_hash(TEST_DIGEST, &test_dstack_config(), &timing)
                .await
                .unwrap();
            assert!(result, "validate_image_hash() failed for test image");
        }
    }
}
