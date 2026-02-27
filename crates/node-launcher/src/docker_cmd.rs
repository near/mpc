use std::collections::BTreeMap;
use std::process::Command;
use std::sync::LazyLock;

use regex::Regex;

use crate::config::{Platform, Sha256Digest};

pub const MPC_CONTAINER_NAME: &str = "mpc-node";
pub const IMAGE_DIGEST_FILE: &str = "/mnt/shared/image-digest.bin";
pub const DSTACK_UNIX_SOCKET: &str = "/var/run/dstack.sock";

// --- DoS caps ---
pub const MAX_PASSTHROUGH_ENV_VARS: usize = 64;
pub const MAX_ENV_VALUE_LEN: usize = 1024;
pub const MAX_TOTAL_ENV_BYTES: usize = 32 * 1024;

/// Env keys that configure the launcher itself. Never passed to the container.
const LAUNCHER_ONLY_KEYS: &[&str] = &[
    "MPC_IMAGE_TAGS",
    "MPC_IMAGE_NAME",
    "MPC_REGISTRY",
    "MPC_HASH_OVERRIDE",
    "RPC_REQUEST_TIMEOUT_SECS",
    "RPC_REQUEST_INTERVAL_SECS",
    "RPC_MAX_ATTEMPTS",
];

/// Keys explicitly denied from the container (raw private keys).
const DENIED_CONTAINER_KEYS: &[&str] = &["MPC_P2P_PRIVATE_KEY", "MPC_ACCOUNT_SK"];

/// Non-MPC keys allowed for backwards compatibility.
const ALLOWED_NON_MPC_KEYS: &[&str] = &[
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

// --- Compiled regexes ---

static MPC_ENV_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^MPC_[A-Z0-9_]{1,64}$").unwrap());

static HOST_ENTRY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9\-\.]+:\d{1,3}(\.\d{1,3}){3}$").unwrap());

static PORT_MAPPING_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d{1,5}):(\d{1,5})$").unwrap());

/// Block entries starting with '-' (including '--') and shell metacharacters.
static INVALID_HOST_ENTRY_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[;&|`$\\<>\-]|^--").unwrap());

#[derive(Debug, thiserror::Error)]
pub enum DockerCmdError {
    #[error("too many env vars to pass through (>{MAX_PASSTHROUGH_ENV_VARS})")]
    TooManyEnvVars,
    #[error("total env payload too large (>{MAX_TOTAL_ENV_BYTES} bytes)")]
    EnvPayloadTooLarge,
    #[error("unsafe docker command: LD_PRELOAD detected")]
    LdPreloadDetected,
}

/// Returns true if the string contains unsafe control characters.
/// Rejects NUL, CR, LF, and other ASCII control chars (< 0x20) except tab.
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

/// Validates that an env value contains no unsafe control characters,
/// no LD_PRELOAD substring, and is within size limits.
pub fn is_safe_env_value(value: &str) -> bool {
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

/// Returns true if the key is allowed to be passed to the MPC container.
pub fn is_allowed_container_env_key(key: &str) -> bool {
    if DENIED_CONTAINER_KEYS.contains(&key) {
        return false;
    }
    if MPC_ENV_KEY_RE.is_match(key) {
        return true;
    }
    if ALLOWED_NON_MPC_KEYS.contains(&key) {
        return true;
    }
    false
}

fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

/// Validates a "hostname:ip" entry.
pub fn is_valid_host_entry(entry: &str) -> bool {
    if !HOST_ENTRY_RE.is_match(entry) {
        return false;
    }
    // Split on first ':' to get the IP part
    if let Some((_host, ip)) = entry.split_once(':') {
        return is_valid_ip(ip);
    }
    false
}

/// Validates a "host_port:container_port" mapping.
pub fn is_valid_port_mapping(entry: &str) -> bool {
    let Some(caps) = PORT_MAPPING_RE.captures(entry) else {
        return false;
    };
    let Ok(host_port) = caps[1].parse::<u32>() else {
        return false;
    };
    let Ok(container_port) = caps[2].parse::<u32>() else {
        return false;
    };
    (1..=65535).contains(&host_port) && (1..=65535).contains(&container_port)
}

/// Ensure host entry does not contain unsafe characters or LD_PRELOAD.
fn is_safe_host_entry(entry: &str) -> bool {
    if INVALID_HOST_ENTRY_PATTERN.is_match(entry) {
        return false;
    }
    if entry.contains("LD_PRELOAD") {
        return false;
    }
    true
}

/// Ensure port mapping does not contain unsafe characters.
fn is_safe_port_mapping(mapping: &str) -> bool {
    !INVALID_HOST_ENTRY_PATTERN.is_match(mapping)
}

/// Build the complete docker run command. This is the security boundary.
pub fn build_docker_cmd(
    platform: Platform,
    user_env: &BTreeMap<String, String>,
    image_digest: &Sha256Digest,
) -> Result<Vec<String>, DockerCmdError> {
    let bare_digest = image_digest.bare_hex();

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

    let mut passed_env_count: usize = 0;
    let mut total_env_bytes: usize = 0;

    // Deterministic iteration (BTreeMap is sorted)
    for (key, value) in user_env {
        if LAUNCHER_ONLY_KEYS.contains(&key.as_str()) {
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
            return Err(DockerCmdError::TooManyEnvVars);
        }

        total_env_bytes += key.len() + 1 + value.len();
        if total_env_bytes > MAX_TOTAL_ENV_BYTES {
            return Err(DockerCmdError::EnvPayloadTooLarge);
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
        image_digest.full().to_string(), // Docker must get the FULL digest
    ]);

    tracing::info!("docker cmd: {}", cmd.join(" "));

    // Final LD_PRELOAD safeguard
    let cmd_str = cmd.join(" ");
    if cmd_str.contains("LD_PRELOAD") {
        return Err(DockerCmdError::LdPreloadDetected);
    }

    Ok(cmd)
}

/// Stop and remove the MPC container if it exists.
pub fn remove_existing_container() {
    let Ok(output) = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}"])
        .output()
    else {
        tracing::warn!("Failed to list docker containers");
        return;
    };

    let names = String::from_utf8_lossy(&output.stdout);
    if names.lines().any(|name| name == MPC_CONTAINER_NAME) {
        tracing::info!("Removing existing container: {MPC_CONTAINER_NAME}");
        let _ = Command::new("docker")
            .args(["rm", "-f", MPC_CONTAINER_NAME])
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_digest(hex_char: char) -> Sha256Digest {
        Sha256Digest::parse(&hex_char.to_string().repeat(64)).unwrap()
    }

    fn base_env() -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("MPC_ACCOUNT_ID".into(), "mpc-user-123".into());
        env
    }

    // --- has_control_chars tests ---

    #[test]
    fn test_has_control_chars_rejects_newline_and_cr() {
        assert!(has_control_chars("a\nb"));
        assert!(has_control_chars("a\rb"));
    }

    #[test]
    fn test_has_control_chars_rejects_other_control_but_allows_tab() {
        assert!(!has_control_chars("a\tb"));
        assert!(has_control_chars(&format!("a{}b", char::from(0x1f))));
    }

    // --- is_safe_env_value tests ---

    #[test]
    fn test_is_safe_env_value_rejects_control_chars() {
        assert!(!is_safe_env_value("ok\nno"));
        assert!(!is_safe_env_value("ok\rno"));
        assert!(!is_safe_env_value(&format!("ok{}no", char::from(0x1f))));
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

    // --- is_allowed_container_env_key tests ---

    #[test]
    fn test_allowed_key_mpc_prefix_uppercase() {
        assert!(is_allowed_container_env_key("MPC_FOO"));
        assert!(is_allowed_container_env_key("MPC_FOO_123"));
        assert!(is_allowed_container_env_key("MPC_A_B_C"));
    }

    #[test]
    fn test_allowed_key_rejects_lowercase_or_invalid() {
        assert!(!is_allowed_container_env_key("MPC_foo"));
        assert!(!is_allowed_container_env_key("MPC-FOO"));
        assert!(!is_allowed_container_env_key("MPC.FOO"));
        assert!(!is_allowed_container_env_key("MPC_"));
    }

    #[test]
    fn test_allowed_key_compat_non_mpc_keys() {
        assert!(is_allowed_container_env_key("RUST_LOG"));
        assert!(is_allowed_container_env_key("RUST_BACKTRACE"));
        assert!(is_allowed_container_env_key("NEAR_BOOT_NODES"));
    }

    #[test]
    fn test_allowed_key_denies_sensitive() {
        assert!(!is_allowed_container_env_key("MPC_P2P_PRIVATE_KEY"));
        assert!(!is_allowed_container_env_key("MPC_ACCOUNT_SK"));
    }

    // --- host/port validation tests ---

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

    // --- build_docker_cmd tests ---

    #[test]
    fn test_build_docker_cmd_sanitizes_ports_and_hosts() {
        let mut env = base_env();
        env.insert("PORTS".into(), "11780:11780,--env BAD=1".into());
        env.insert(
            "EXTRA_HOSTS".into(),
            "node:192.168.1.1,--volume /:/mnt".into(),
        );

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        let cmd_str = cmd.join(" ");

        assert!(cmd_str.contains("MPC_ACCOUNT_ID=mpc-user-123"));
        assert!(cmd.contains(&"11780:11780".to_string()));
        assert!(cmd.contains(&"node:192.168.1.1".to_string()));
        assert!(!cmd.iter().any(|a| a.contains("BAD=1")));
        assert!(!cmd.iter().any(|a| a.contains("/:/mnt")));
    }

    #[test]
    fn test_extra_hosts_does_not_allow_ld_preload() {
        let mut env = base_env();
        env.insert(
            "EXTRA_HOSTS".into(),
            "host:1.2.3.4,--env LD_PRELOAD=/evil.so".into(),
        );

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        assert!(cmd.contains(&"host:1.2.3.4".to_string()));
        assert!(!cmd.iter().any(|a| a.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ports_does_not_allow_volume_injection() {
        let mut env = base_env();
        env.insert("PORTS".into(), "2200:2200,--volume /:/mnt".into());

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        assert!(cmd.contains(&"2200:2200".to_string()));
        assert!(!cmd.iter().any(|a| a.contains("/:/mnt")));
    }

    #[test]
    fn test_invalid_env_key_is_ignored() {
        let mut env = base_env();
        env.insert("BAD_KEY".into(), "should_not_be_used".into());

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        let cmd_str = cmd.join(" ");
        assert!(!cmd_str.contains("should_not_be_used"));
        assert!(cmd_str.contains("MPC_ACCOUNT_ID=mpc-user-123"));
    }

    #[test]
    fn test_mpc_backup_encryption_key_is_allowed() {
        let mut env = BTreeMap::new();
        env.insert("MPC_BACKUP_ENCRYPTION_KEY_HEX".into(), "0".repeat(64));

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        let cmd_str = cmd.join(" ");
        assert!(cmd_str.contains(&format!("MPC_BACKUP_ENCRYPTION_KEY_HEX={}", "0".repeat(64))));
    }

    #[test]
    fn test_malformed_extra_host_is_ignored() {
        let mut env = base_env();
        env.insert(
            "EXTRA_HOSTS".into(),
            "badhostentry,no-colon,also--bad".into(),
        );

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        assert!(!cmd.contains(&"--add-host".to_string()));
    }

    #[test]
    fn test_env_value_with_shell_injection_is_passed() {
        // Command::new does not interpret shell, so this is safe
        let mut env = BTreeMap::new();
        env.insert("MPC_ACCOUNT_ID".into(), "safe; rm -rf /".into());

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        assert!(cmd.contains(&"MPC_ACCOUNT_ID=safe; rm -rf /".to_string()));
    }

    #[test]
    fn test_ld_preload_injection_blocked_env_key() {
        let mut env = base_env();
        env.insert("--env LD_PRELOAD".into(), "/path/to/malloc.so".into());

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        assert!(!cmd.iter().any(|a| a.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ld_preload_injection_blocked_env_value() {
        let mut env = base_env();
        env.insert(
            "MPC_ACCOUNT_ID".into(),
            "safe, --env LD_PRELOAD=/path/to/malloc.so".into(),
        );

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        assert!(!cmd.iter().any(|a| a.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ld_preload_in_extra_hosts() {
        let mut env = base_env();
        env.insert(
            "EXTRA_HOSTS".into(),
            "host1:192.168.0.1,host2:192.168.0.2,--env LD_PRELOAD=/evil.so".into(),
        );

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        assert!(cmd.contains(&"--add-host".to_string()));
        assert!(!cmd.iter().any(|a| a.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ld_preload_in_ports() {
        let mut env = base_env();
        env.insert(
            "PORTS".into(),
            "11780:11780,--env LD_PRELOAD=/evil.so".into(),
        );

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        assert!(cmd.contains(&"-p".to_string()));
        assert!(!cmd.iter().any(|a| a.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ld_preload_dash_e_variant() {
        let mut env = base_env();
        env.insert("-e LD_PRELOAD".into(), "/evil.so".into());

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        assert!(!cmd.iter().any(|a| a.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ld_preload_in_extra_hosts_dash_e() {
        let mut env = base_env();
        env.insert(
            "EXTRA_HOSTS".into(),
            "host1:192.168.0.1,host2:192.168.0.2,-e LD_PRELOAD=/evil.so".into(),
        );

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        assert!(cmd.contains(&"--add-host".to_string()));
        assert!(!cmd.iter().any(|a| a.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_ld_preload_in_ports_dash_e() {
        let mut env = base_env();
        env.insert("PORTS".into(), "11780:11780,-e LD_PRELOAD=/evil.so".into());

        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('a')).unwrap();
        assert!(cmd.contains(&"-p".to_string()));
        assert!(!cmd.iter().any(|a| a.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_build_docker_cmd_blocks_sensitive_keys() {
        let mut env = base_env();
        env.insert("MPC_P2P_PRIVATE_KEY".into(), "supersecret".into());
        env.insert("MPC_ACCOUNT_SK".into(), "supersecret2".into());

        let cmd = build_docker_cmd(Platform::NonTee, &env, &make_digest('a')).unwrap();
        let cmd_str = cmd.join(" ");
        assert!(!cmd_str.contains("MPC_P2P_PRIVATE_KEY"));
        assert!(!cmd_str.contains("MPC_ACCOUNT_SK"));
    }

    #[test]
    fn test_build_docker_cmd_skips_launcher_keys() {
        let mut env = base_env();
        env.insert("RPC_MAX_ATTEMPTS".into(), "5".into());
        env.insert("MPC_HASH_OVERRIDE".into(), "sha256:abc".into());

        let cmd = build_docker_cmd(Platform::NonTee, &env, &make_digest('a')).unwrap();
        let cmd_str = cmd.join(" ");
        assert!(!cmd_str.contains("RPC_MAX_ATTEMPTS=5"));
        assert!(!cmd_str.contains("MPC_HASH_OVERRIDE"));
    }

    #[test]
    fn test_build_docker_cmd_allows_arbitrary_mpc_prefix() {
        let mut env = base_env();
        env.insert("MPC_NEW_FEATURE_FLAG".into(), "1".into());
        env.insert("MPC_SOME_CONFIG".into(), "value".into());

        let cmd = build_docker_cmd(Platform::NonTee, &env, &make_digest('a')).unwrap();
        let cmd_str = cmd.join(" ");
        assert!(cmd_str.contains("MPC_NEW_FEATURE_FLAG=1"));
        assert!(cmd_str.contains("MPC_SOME_CONFIG=value"));
    }

    #[test]
    fn test_build_docker_cmd_rejects_env_value_with_newline() {
        let mut env = base_env();
        env.insert("MPC_NEW_FEATURE_FLAG".into(), "ok\nbad".into());

        let cmd = build_docker_cmd(Platform::NonTee, &env, &make_digest('a')).unwrap();
        let cmd_str = cmd.join(" ");
        assert!(!cmd_str.contains("MPC_NEW_FEATURE_FLAG"));
    }

    #[test]
    fn test_build_docker_cmd_enforces_max_env_count() {
        let mut env = base_env();
        for i in 0..=MAX_PASSTHROUGH_ENV_VARS {
            env.insert(format!("MPC_X_{i}"), "1".into());
        }
        assert!(matches!(
            build_docker_cmd(Platform::NonTee, &env, &make_digest('a')),
            Err(DockerCmdError::TooManyEnvVars)
        ));
    }

    #[test]
    fn test_build_docker_cmd_enforces_total_env_bytes() {
        let mut env = base_env();
        for i in 0..40 {
            env.insert(format!("MPC_BIG_{i}"), "a".repeat(MAX_ENV_VALUE_LEN));
        }
        assert!(matches!(
            build_docker_cmd(Platform::NonTee, &env, &make_digest('a')),
            Err(DockerCmdError::EnvPayloadTooLarge)
        ));
    }

    #[test]
    fn test_build_docker_cmd_tee_has_dstack_mount() {
        let env = base_env();
        let cmd = build_docker_cmd(Platform::Tee, &env, &make_digest('c')).unwrap();
        let cmd_str = cmd.join(" ");
        assert!(cmd_str.contains(&format!("DSTACK_ENDPOINT={DSTACK_UNIX_SOCKET}")));
        assert!(cmd_str.contains(&format!("{DSTACK_UNIX_SOCKET}:{DSTACK_UNIX_SOCKET}")));
    }

    #[test]
    fn test_build_docker_cmd_nontee_no_dstack_mount() {
        let env = base_env();
        let cmd = build_docker_cmd(Platform::NonTee, &env, &make_digest('c')).unwrap();
        let cmd_str = cmd.join(" ");
        assert!(!cmd_str.contains("DSTACK_ENDPOINT="));
        assert!(!cmd_str.contains(&format!("{DSTACK_UNIX_SOCKET}:{DSTACK_UNIX_SOCKET}")));
    }

    #[test]
    fn test_build_docker_cmd_security_opts_and_volumes() {
        let env = base_env();
        let digest = make_digest('a');
        let cmd = build_docker_cmd(Platform::NonTee, &env, &digest).unwrap();
        let cmd_str = cmd.join(" ");

        assert!(cmd_str.contains("--security-opt no-new-privileges:true"));
        assert!(cmd_str.contains("/tapp:/tapp:ro"));
        assert!(cmd_str.contains("shared-volume:/mnt/shared"));
        assert!(cmd_str.contains("mpc-data:/data"));
        assert!(cmd_str.contains(&format!("--name {MPC_CONTAINER_NAME}")));
        assert!(cmd_str.contains("--detach"));
        // Image digest should be the last argument
        assert_eq!(cmd.last().unwrap(), digest.full());
    }
}
