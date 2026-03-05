use std::sync::LazyLock;

use regex::Regex;

/// Hard caps to prevent DoS via huge env payloads (matching Python launcher).
pub(crate) const MAX_PASSTHROUGH_ENV_VARS: usize = 64;
pub(crate) const MAX_ENV_VALUE_LEN: usize = 1024;
pub(crate) const MAX_TOTAL_ENV_BYTES: usize = 32 * 1024; // 32 KB

/// Never pass raw private keys via launcher.
const DENIED_CONTAINER_ENV_KEYS: &[&str] = &["MPC_P2P_PRIVATE_KEY", "MPC_ACCOUNT_SK"];

/// Matches `MPC_[A-Z0-9_]{1,64}` — same pattern as the Python launcher.
static MPC_ENV_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^MPC_[A-Z0-9_]{1,64}$").unwrap());

/// Non-MPC keys that are explicitly allowed for backwards compatibility.
const COMPAT_ALLOWED_KEYS: &[&str] = &["RUST_LOG", "RUST_BACKTRACE", "NEAR_BOOT_NODES"];

// ---------------------------------------------------------------------------
// Key validation
// ---------------------------------------------------------------------------

/// Validates an extra env key (from the catch-all `extra_env` map).
///
/// - Must match `MPC_[A-Z0-9_]{1,64}` **or** be in the compat allowlist
/// - Must not be in the deny list
pub(crate) fn validate_env_key(key: &str) -> Result<(), crate::error::LauncherError> {
    if DENIED_CONTAINER_ENV_KEYS.contains(&key) {
        return Err(crate::error::LauncherError::UnsafeEnvValue {
            key: key.to_owned(),
            reason: "denied key".into(),
        });
    }
    if MPC_ENV_KEY_RE.is_match(key) || COMPAT_ALLOWED_KEYS.contains(&key) {
        return Ok(());
    }
    Err(crate::error::LauncherError::UnsafeEnvValue {
        key: key.to_owned(),
        reason: "key does not match allowlist".into(),
    })
}

// ---------------------------------------------------------------------------
// Value validation
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

/// Validates an env value (applied to ALL vars, typed and extra).
///
/// - Length <= `MAX_ENV_VALUE_LEN`
/// - No ASCII control characters (except tab)
/// - Does not contain `LD_PRELOAD`
pub(crate) fn validate_env_value(
    key: &str,
    value: &str,
) -> Result<(), crate::error::LauncherError> {
    if value.len() > MAX_ENV_VALUE_LEN {
        return Err(crate::error::LauncherError::UnsafeEnvValue {
            key: key.to_owned(),
            reason: format!("value too long ({} > {MAX_ENV_VALUE_LEN})", value.len()),
        });
    }
    if has_control_chars(value) {
        return Err(crate::error::LauncherError::UnsafeEnvValue {
            key: key.to_owned(),
            reason: "contains control characters".into(),
        });
    }
    if value.contains("LD_PRELOAD") {
        return Err(crate::error::LauncherError::UnsafeEnvValue {
            key: key.to_owned(),
            reason: "contains LD_PRELOAD".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Key validation tests --

    #[test]
    fn key_allows_mpc_prefix_uppercase() {
        assert!(validate_env_key("MPC_FOO").is_ok());
        assert!(validate_env_key("MPC_FOO_123").is_ok());
        assert!(validate_env_key("MPC_A_B_C").is_ok());
    }

    #[test]
    fn key_rejects_lowercase_or_invalid_format() {
        assert!(validate_env_key("MPC_foo").is_err());
        assert!(validate_env_key("MPC-FOO").is_err());
        assert!(validate_env_key("MPC.FOO").is_err());
        assert!(validate_env_key("MPC_").is_err());
    }

    #[test]
    fn key_allows_compat_non_mpc_keys() {
        assert!(validate_env_key("RUST_LOG").is_ok());
        assert!(validate_env_key("RUST_BACKTRACE").is_ok());
        assert!(validate_env_key("NEAR_BOOT_NODES").is_ok());
    }

    #[test]
    fn key_denies_sensitive_keys() {
        assert!(validate_env_key("MPC_P2P_PRIVATE_KEY").is_err());
        assert!(validate_env_key("MPC_ACCOUNT_SK").is_err());
    }

    #[test]
    fn key_rejects_unknown_non_mpc_key() {
        assert!(validate_env_key("BAD_KEY").is_err());
        assert!(validate_env_key("HOME").is_err());
    }

    // -- Value validation tests --

    #[test]
    fn value_rejects_control_chars() {
        assert!(validate_env_value("K", "ok\nno").is_err());
        assert!(validate_env_value("K", "ok\rno").is_err());
        assert!(validate_env_value("K", &format!("a{}b", '\x1F')).is_err());
    }

    #[test]
    fn value_allows_tab() {
        assert!(validate_env_value("K", "a\tb").is_ok());
    }

    #[test]
    fn value_rejects_ld_preload() {
        assert!(validate_env_value("K", "LD_PRELOAD=/tmp/x.so").is_err());
        assert!(validate_env_value("K", "foo LD_PRELOAD bar").is_err());
    }

    #[test]
    fn value_rejects_too_long() {
        assert!(validate_env_value("K", &"a".repeat(MAX_ENV_VALUE_LEN + 1)).is_err());
        assert!(validate_env_value("K", &"a".repeat(MAX_ENV_VALUE_LEN)).is_ok());
    }

    #[test]
    fn value_accepts_normal() {
        assert!(validate_env_value("K", "hello-world").is_ok());
        assert!(validate_env_value("K", "192.168.1.1").is_ok());
        assert!(validate_env_value("K", "info,mpc_node=debug").is_ok());
    }
}
