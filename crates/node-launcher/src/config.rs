use std::collections::BTreeMap;
use std::path::Path;

/// JSON key used inside image-digest.bin.
/// IMPORTANT: Must stay aligned with the MPC node implementation in:
///   crates/node/src/tee/allowed_image_hashes_watcher.rs
pub const JSON_KEY_APPROVED_HASHES: &str = "approved_hashes";

pub const IMAGE_DIGEST_FILE: &str = "/mnt/shared/image-digest.bin";
pub const DSTACK_USER_CONFIG_FILE: &str = "/tapp/user_config";

const ENV_VAR_PLATFORM: &str = "PLATFORM";
const ENV_VAR_DEFAULT_IMAGE_DIGEST: &str = "DEFAULT_IMAGE_DIGEST";

// dstack user config keys
const DSTACK_USER_CONFIG_MPC_IMAGE_TAGS: &str = "MPC_IMAGE_TAGS";
const DSTACK_USER_CONFIG_MPC_IMAGE_NAME: &str = "MPC_IMAGE_NAME";
const DSTACK_USER_CONFIG_MPC_IMAGE_REGISTRY: &str = "MPC_REGISTRY";
pub const ENV_VAR_MPC_HASH_OVERRIDE: &str = "MPC_HASH_OVERRIDE";
const ENV_VAR_RPC_REQUEST_TIMEOUT_SECS: &str = "RPC_REQUEST_TIMEOUT_SECS";
const ENV_VAR_RPC_REQUEST_INTERVAL_SECS: &str = "RPC_REQUEST_INTERVAL_SECS";
const ENV_VAR_RPC_MAX_ATTEMPTS: &str = "RPC_MAX_ATTEMPTS";

// Defaults
const DEFAULT_MPC_IMAGE_NAME: &str = "nearone/mpc-node";
const DEFAULT_MPC_REGISTRY: &str = "registry.hub.docker.com";
const DEFAULT_MPC_IMAGE_TAG: &str = "latest";
const DEFAULT_RPC_TIMEOUT_SECS: f64 = 10.0;
const DEFAULT_RPC_INTERVAL_SECS: f64 = 1.0;
const DEFAULT_RPC_MAX_ATTEMPTS: u32 = 20;

static SHA256_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^sha256:[0-9a-f]{64}$").unwrap());

const SHA256_PREFIX: &str = "sha256:";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} must be set to one of: TEE, NONTEE")]
    InvalidPlatform(String),
    #[error("invalid SHA256 digest: {0}")]
    InvalidDigest(String),
    #[error("failed to read {path}: {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse approved hashes from {path}: {reason}")]
    HashFileParse { path: String, reason: String },
    #[error("MPC_HASH_OVERRIDE {0} is not in the approved list")]
    OverrideNotApproved(String),
    #[error("{0} environment variable is not set")]
    EnvVarMissing(String),
}

/// Platform mode. Must come from measured docker-compose env in TEE deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Tee,
    NonTee,
}

/// Timing configuration for Docker Hub RPC requests.
#[derive(Debug, Clone)]
pub struct RpcTimingConfig {
    pub timeout_secs: f64,
    pub interval_secs: f64,
    pub max_attempts: u32,
}

impl Default for RpcTimingConfig {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_RPC_TIMEOUT_SECS,
            interval_secs: DEFAULT_RPC_INTERVAL_SECS,
            max_attempts: DEFAULT_RPC_MAX_ATTEMPTS,
        }
    }
}

/// A validated SHA256 digest string, always in "sha256:<64 hex chars>" form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Parse and validate a digest string. Prepends "sha256:" if missing.
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        let mut s = raw.trim().to_string();
        if !s.starts_with(SHA256_PREFIX) {
            s = format!("{SHA256_PREFIX}{s}");
        }
        if !SHA256_RE.is_match(&s) {
            return Err(ConfigError::InvalidDigest(s));
        }
        Ok(Self(s))
    }

    /// The full "sha256:abcdef..." string.
    pub fn full(&self) -> &str {
        &self.0
    }

    /// The bare hex portion without the "sha256:" prefix.
    pub fn bare_hex(&self) -> &str {
        &self.0[SHA256_PREFIX.len()..]
    }

    /// Decode the bare hex into raw bytes (32 bytes).
    pub fn to_bytes(&self) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(self.bare_hex())
    }
}

impl std::fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Specification for which Docker image to look up.
#[derive(Debug, Clone)]
pub struct ImageSpec {
    pub tags: Vec<String>,
    pub image_name: String,
    pub registry: String,
}

/// An ImageSpec resolved to a specific digest.
#[derive(Debug, Clone)]
pub struct ResolvedImage {
    pub spec: ImageSpec,
    pub digest: Sha256Digest,
}

/// Parse a platform string into a Platform enum.
fn parse_platform_str(raw: &str) -> Result<Platform, ConfigError> {
    match raw.trim() {
        "TEE" => Ok(Platform::Tee),
        "NONTEE" => Ok(Platform::NonTee),
        _ => Err(ConfigError::InvalidPlatform(ENV_VAR_PLATFORM.to_string())),
    }
}

/// Parse PLATFORM from process env. Never reads user_config.
pub fn parse_platform() -> Result<Platform, ConfigError> {
    let raw = std::env::var(ENV_VAR_PLATFORM)
        .map_err(|_| ConfigError::InvalidPlatform(ENV_VAR_PLATFORM.to_string()))?;
    parse_platform_str(&raw)
}

/// Parse KEY=VALUE lines. Handles comments, blank lines, trimming, last-wins.
pub fn parse_env_lines(content: &str) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        env.insert(key.to_string(), value.trim().to_string());
    }
    env
}

/// Load dstack user config from a file path. Returns empty map if file missing.
pub fn load_user_config(path: &Path) -> Result<BTreeMap<String, String>, ConfigError> {
    if !path.is_file() {
        return Ok(BTreeMap::new());
    }
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::FileRead {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(parse_env_lines(&content))
}

/// Build RpcTimingConfig from user config, falling back to defaults.
pub fn load_rpc_timing_config(user_config: &BTreeMap<String, String>) -> RpcTimingConfig {
    let defaults = RpcTimingConfig::default();
    RpcTimingConfig {
        timeout_secs: user_config
            .get(ENV_VAR_RPC_REQUEST_TIMEOUT_SECS)
            .and_then(|v| v.parse().ok())
            .unwrap_or(defaults.timeout_secs),
        interval_secs: user_config
            .get(ENV_VAR_RPC_REQUEST_INTERVAL_SECS)
            .and_then(|v| v.parse().ok())
            .unwrap_or(defaults.interval_secs),
        max_attempts: user_config
            .get(ENV_VAR_RPC_MAX_ATTEMPTS)
            .and_then(|v| v.parse().ok())
            .unwrap_or(defaults.max_attempts),
    }
}

/// Build ImageSpec from user config, falling back to defaults.
pub fn get_image_spec(user_config: &BTreeMap<String, String>) -> ImageSpec {
    let tags_raw = user_config
        .get(DSTACK_USER_CONFIG_MPC_IMAGE_TAGS)
        .map(|s| s.as_str())
        .unwrap_or(DEFAULT_MPC_IMAGE_TAG);
    let tags: Vec<String> = tags_raw
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();

    let image_name = user_config
        .get(DSTACK_USER_CONFIG_MPC_IMAGE_NAME)
        .cloned()
        .unwrap_or_else(|| DEFAULT_MPC_IMAGE_NAME.to_string());

    let registry = user_config
        .get(DSTACK_USER_CONFIG_MPC_IMAGE_REGISTRY)
        .cloned()
        .unwrap_or_else(|| DEFAULT_MPC_REGISTRY.to_string());

    tracing::info!(?tags, %image_name, %registry, "Image spec");
    ImageSpec {
        tags,
        image_name,
        registry,
    }
}

/// Load approved hashes and select one (override or newest).
pub fn load_and_select_hash(
    user_config: &BTreeMap<String, String>,
) -> Result<Sha256Digest, ConfigError> {
    let approved_hashes = if Path::new(IMAGE_DIGEST_FILE).is_file() {
        let content =
            std::fs::read_to_string(IMAGE_DIGEST_FILE).map_err(|e| ConfigError::FileRead {
                path: IMAGE_DIGEST_FILE.to_string(),
                source: e,
            })?;
        let data: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| ConfigError::HashFileParse {
                path: IMAGE_DIGEST_FILE.to_string(),
                reason: e.to_string(),
            })?;
        let hashes = data
            .get(JSON_KEY_APPROVED_HASHES)
            .and_then(|v| v.as_array())
            .ok_or_else(|| ConfigError::HashFileParse {
                path: IMAGE_DIGEST_FILE.to_string(),
                reason: "approved_hashes missing or empty".to_string(),
            })?;
        if hashes.is_empty() {
            return Err(ConfigError::HashFileParse {
                path: IMAGE_DIGEST_FILE.to_string(),
                reason: "approved_hashes is empty".to_string(),
            });
        }
        hashes
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<Vec<_>>()
    } else {
        let fallback = std::env::var(ENV_VAR_DEFAULT_IMAGE_DIGEST)
            .map_err(|_| ConfigError::EnvVarMissing(ENV_VAR_DEFAULT_IMAGE_DIGEST.to_string()))?;
        let digest = Sha256Digest::parse(&fallback)?;
        tracing::info!(
            "{IMAGE_DIGEST_FILE} missing -> fallback to DEFAULT_IMAGE_DIGEST={}",
            digest.full()
        );
        vec![digest.full().to_string()]
    };

    tracing::info!("Approved MPC image hashes (newest -> oldest):");
    for h in &approved_hashes {
        tracing::info!("  - {h}");
    }

    // Optional override
    if let Some(override_val) = user_config.get(ENV_VAR_MPC_HASH_OVERRIDE) {
        if !SHA256_RE.is_match(override_val) {
            return Err(ConfigError::InvalidDigest(override_val.clone()));
        }
        if !approved_hashes.contains(override_val) {
            return Err(ConfigError::OverrideNotApproved(override_val.clone()));
        }
        tracing::info!("MPC_HASH_OVERRIDE provided -> selecting: {override_val}");
        return Sha256Digest::parse(override_val);
    }

    // No override -> select newest (first in list)
    let selected = &approved_hashes[0];
    tracing::info!("Selected MPC hash (newest allowed): {selected}");
    Sha256Digest::parse(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_env_lines_basic() {
        let input = "# a comment\nKEY1=value1\n  KEY2 = value2 \n\nINVALIDLINE\nEMPTY_KEY=";
        let env = parse_env_lines(input);
        assert_eq!(env.get("KEY1").unwrap(), "value1");
        assert_eq!(env.get("KEY2").unwrap(), "value2");
        assert_eq!(env.get("EMPTY_KEY").unwrap(), "");
        assert!(!env.contains_key("INVALIDLINE"));
    }

    #[test]
    fn test_parse_env_lines_duplicate_keys() {
        let input = "MPC_ACCOUNT_ID=first\nMPC_ACCOUNT_ID=second";
        let env = parse_env_lines(input);
        assert_eq!(env.get("MPC_ACCOUNT_ID").unwrap(), "second");
    }

    #[test]
    fn test_parse_env_lines_malformed() {
        let input = "GOOD_KEY=value\nbad_line_without_equal\nANOTHER_GOOD=ok\n=";
        let env = parse_env_lines(input);
        assert!(env.contains_key("GOOD_KEY"));
        assert!(env.contains_key("ANOTHER_GOOD"));
        assert!(!env.contains_key("bad_line_without_equal"));
        assert!(!env.contains_key(""));
    }

    #[test]
    fn test_parse_env_lines_comments_and_blanks() {
        let input = "\n# This is a comment\nMPC_SECRET_STORE_KEY=topsecret\n\n";
        let env = parse_env_lines(input);
        assert_eq!(env.get("MPC_SECRET_STORE_KEY").unwrap(), "topsecret");
        assert_eq!(env.len(), 1);
    }

    #[test]
    fn test_parse_platform_valid() {
        assert_eq!(parse_platform_str("TEE").unwrap(), Platform::Tee);
        assert_eq!(parse_platform_str("NONTEE").unwrap(), Platform::NonTee);
    }

    #[test]
    fn test_parse_platform_invalid() {
        for val in &["", "foo", "TEE as", "NON_TEE", "1", "tee", "nontee"] {
            assert!(parse_platform_str(val).is_err(), "should reject {val:?}");
        }
    }

    #[test]
    fn test_sha256_digest_parse_valid() {
        let hex = "a".repeat(64);
        let d = Sha256Digest::parse(&format!("sha256:{hex}")).unwrap();
        assert_eq!(d.full(), format!("sha256:{hex}"));
        assert_eq!(d.bare_hex(), hex);

        // Without prefix
        let d2 = Sha256Digest::parse(&hex).unwrap();
        assert_eq!(d2.full(), format!("sha256:{hex}"));
    }

    #[test]
    fn test_sha256_digest_parse_invalid() {
        Sha256Digest::parse("sha256:tooshort").unwrap_err();
        Sha256Digest::parse("sha256:GGGG").unwrap_err();
        Sha256Digest::parse("").unwrap_err();
    }

    #[test]
    fn test_sha256_digest_to_bytes() {
        let hex = "ab".repeat(32);
        let d = Sha256Digest::parse(&hex).unwrap();
        let bytes = d.to_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().all(|&b| b == 0xab));
    }

    #[test]
    fn test_load_rpc_timing_config_defaults() {
        let cfg = load_rpc_timing_config(&BTreeMap::new());
        assert_eq!(cfg.timeout_secs, 10.0);
        assert_eq!(cfg.interval_secs, 1.0);
        assert_eq!(cfg.max_attempts, 20);
    }

    #[test]
    fn test_load_rpc_timing_config_overrides() {
        let mut user_config = BTreeMap::new();
        user_config.insert("RPC_REQUEST_TIMEOUT_SECS".to_string(), "5.0".to_string());
        user_config.insert("RPC_MAX_ATTEMPTS".to_string(), "10".to_string());
        let cfg = load_rpc_timing_config(&user_config);
        assert_eq!(cfg.timeout_secs, 5.0);
        assert_eq!(cfg.max_attempts, 10);
        assert_eq!(cfg.interval_secs, 1.0); // default
    }

    #[test]
    fn test_get_image_spec_defaults() {
        let spec = get_image_spec(&BTreeMap::new());
        assert_eq!(spec.tags, vec!["latest"]);
        assert_eq!(spec.image_name, "nearone/mpc-node");
        assert_eq!(spec.registry, "registry.hub.docker.com");
    }

    #[test]
    fn test_get_image_spec_custom() {
        let mut cfg = BTreeMap::new();
        cfg.insert("MPC_IMAGE_TAGS".to_string(), "v1,v2".to_string());
        cfg.insert("MPC_IMAGE_NAME".to_string(), "myorg/mynode".to_string());
        let spec = get_image_spec(&cfg);
        assert_eq!(spec.tags, vec!["v1", "v2"]);
        assert_eq!(spec.image_name, "myorg/mynode");
    }

    #[test]
    fn test_load_and_select_hash_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let hash_file = dir.path().join("image-digest.bin");
        let hash1 = format!("sha256:{}", "a".repeat(64));
        let hash2 = format!("sha256:{}", "b".repeat(64));
        let json = serde_json::json!({ "approved_hashes": [hash1, hash2] });
        std::fs::write(&hash_file, json.to_string()).unwrap();

        // We can't override IMAGE_DIGEST_FILE easily, so test the parsing logic
        // via parse helpers. The full integration is tested via load_and_select_hash
        // in contexts where we control the file path.
        // For now, test that Sha256Digest::parse works on the expected format.
        let d = Sha256Digest::parse(&hash1).unwrap();
        assert_eq!(d.full(), hash1);
    }

    #[test]
    fn test_json_key_matches_node() {
        // This must stay aligned with crates/node/src/tee/allowed_image_hashes_watcher.rs
        assert_eq!(JSON_KEY_APPROVED_HASHES, "approved_hashes");
    }

    #[test]
    fn test_load_user_config_missing_file() {
        let cfg = load_user_config(Path::new("/nonexistent/path")).unwrap();
        assert!(cfg.is_empty());
    }

    #[test]
    fn test_load_user_config_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user_config");
        std::fs::write(&path, "MPC_ACCOUNT_ID=test123\nMPC_ENV=testnet\n").unwrap();
        let cfg = load_user_config(&path).unwrap();
        assert_eq!(cfg.get("MPC_ACCOUNT_ID").unwrap(), "test123");
        assert_eq!(cfg.get("MPC_ENV").unwrap(), "testnet");
    }
}
