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
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("MPC_FOO")]
    #[case("MPC_FOO_123")]
    #[case("MPC_A_B_C")]
    fn key_allows_mpc_prefix_uppercase(#[case] key: &str) {
        assert_matches!(validate_env_key(key), Ok(_));
    }

    #[rstest]
    #[case("MPC_foo")]
    #[case("MPC-FOO")]
    #[case("MPC.FOO")]
    #[case("MPC_")]
    fn key_rejects_lowercase_or_invalid_format(#[case] key: &str) {
        assert_matches!(validate_env_key(key), Err(_));
    }

    #[rstest]
    #[case("RUST_LOG")]
    #[case("RUST_BACKTRACE")]
    #[case("NEAR_BOOT_NODES")]
    fn key_allows_compat_non_mpc_keys(#[case] key: &str) {
        assert_matches!(validate_env_key(key), Ok(_));
    }

    #[rstest]
    #[case("MPC_P2P_PRIVATE_KEY")]
    #[case("MPC_ACCOUNT_SK")]
    fn key_denies_sensitive_keys(#[case] key: &str) {
        assert_matches!(validate_env_key(key), Err(_));
    }

    #[rstest]
    #[case("BAD_KEY")]
    #[case("HOME")]
    fn key_rejects_unknown_non_mpc_key(#[case] key: &str) {
        assert_matches!(validate_env_key(key), Err(_));
    }

    #[rstest]
    #[case("ok\nno")]
    #[case("ok\rno")]
    fn value_rejects_control_chars(#[case] value: &str) {
        assert_matches!(validate_env_value("K", value), Err(_));
    }

    #[test]
    fn value_rejects_control_char_unit_separator() {
        assert_matches!(validate_env_value("K", &format!("a{}b", '\x1F')), Err(_));
    }

    #[test]
    fn value_allows_tab() {
        assert_matches!(validate_env_value("K", "a\tb"), Ok(_));
    }

    #[rstest]
    #[case("LD_PRELOAD=/tmp/x.so")]
    #[case("foo LD_PRELOAD bar")]
    fn value_rejects_ld_preload(#[case] value: &str) {
        assert_matches!(validate_env_value("K", value), Err(_));
    }

    #[test]
    fn value_rejects_too_long() {
        assert_matches!(
            validate_env_value("K", &"a".repeat(MAX_ENV_VALUE_LEN + 1)),
            Err(_)
        );
    }

    #[test]
    fn value_accepts_at_length_limit() {
        assert_matches!(
            validate_env_value("K", &"a".repeat(MAX_ENV_VALUE_LEN)),
            Ok(_)
        );
    }

    #[rstest]
    #[case("hello-world")]
    #[case("192.168.1.1")]
    #[case("info,mpc_node=debug")]
    fn value_accepts_normal(#[case] value: &str) {
        assert_matches!(validate_env_value("K", value), Ok(_));
    }
}
