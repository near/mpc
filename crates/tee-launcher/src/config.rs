use launcher_interface::types::TeeConfig;

use crate::error::LauncherError;
use crate::types::Platform;

/// Config keys that are not allowed in TEE mode because they could allow
/// an operator to exfiltrate key material.
/// Must match the field names in node-config's `StartConfig`.
const TEE_BLOCKED_KEYS: &[&str] = &["gcp"];

/// Inject launcher-controlled config section (`tee`) into the user-provided
/// MPC node config table.  Returns an error if the user config already
/// contains a reserved key.
///
/// In TEE mode, keys listed in `TEE_BLOCKED_KEYS` are also rejected.
pub fn intercept_node_config(
    mut node_config: toml::Table,
    tee_config: &TeeConfig,
    platform: Platform,
) -> Result<toml::Table, LauncherError> {
    insert_reserved(
        &mut node_config,
        "tee",
        toml::Value::try_from(tee_config).expect("tee config serializes to TOML"),
    )?;

    if platform == Platform::Tee {
        for key in TEE_BLOCKED_KEYS {
            if node_config.contains_key(*key) {
                return Err(LauncherError::TeeRestrictedConfigKey(key.to_string()));
            }
        }
    }

    Ok(node_config)
}

/// Insert `value` under `key` in `table`, returning an error if the key
/// already exists. Used to inject launcher-controlled sections into user config.
fn insert_reserved(
    table: &mut toml::Table,
    key: &str,
    value: toml::Value,
) -> Result<(), LauncherError> {
    match table.entry(key) {
        toml::map::Entry::Vacant(vacant) => {
            vacant.insert(value);
            Ok(())
        }
        toml::map::Entry::Occupied(_) => Err(LauncherError::ReservedConfigKey(key.to_string())),
    }
}

/// Validate a Docker image reference: `[registry[:port]/]name[:tag]`.
///
/// Checks structural validity beyond just safe characters:
/// - Must not be empty
/// - Must start with an alphanumeric character
/// - Must not end with `:`, `/`, or `.`
/// - Must not contain `//`, `::`, or `:.`
/// - Only allows `[a-zA-Z0-9._/:-]`
///
/// This prevents YAML injection when the value is interpolated into the
/// compose template, while also catching obviously malformed references.
pub fn validate_image_reference(image_ref: &str) -> Result<(), LauncherError> {
    let is_valid = !image_ref.is_empty()
        && image_ref.bytes().next().unwrap().is_ascii_alphanumeric()
        && image_ref.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b == b'/'
                || b == b'-'
                || b == b'.'
                || b == b'_'
                || b == b':'
        })
        && !image_ref.ends_with(':')
        && !image_ref.ends_with('/')
        && !image_ref.ends_with('.')
        && !image_ref.contains("//")
        && !image_ref.contains("::")
        && !image_ref.contains(":.");
    if !is_valid {
        return Err(LauncherError::InvalidImageName(image_ref.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use launcher_interface::types::{DockerSha256Digest, TeeAuthorityConfig, TeeConfig};

    use super::*;

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

    fn sample_tee_config() -> TeeConfig {
        TeeConfig {
            authority: TeeAuthorityConfig::Dstack {
                dstack_endpoint: "/var/run/dstack.sock".to_string(),
            },
            image_hash: sample_digest(),
            latest_allowed_hash_file_path: "/mnt/shared/image-digest.bin".into(),
        }
    }

    #[test]
    fn intercept_config_injects_tee_config() {
        // given
        let config: toml::Table = toml::from_str(r#"home_dir = "/data""#).unwrap();

        // when
        let result = intercept_node_config(config, &sample_tee_config(), Platform::Tee).unwrap();

        // then
        assert!(result.contains_key("tee"));
        assert_eq!(result["home_dir"].as_str(), Some("/data"));
    }

    #[test]
    fn intercept_config_rejects_user_provided_tee_key() {
        // given
        let config: toml::Table = toml::from_str(
            r#"[tee]
type = "Local"
"#,
        )
        .unwrap();

        // when
        let result = intercept_node_config(config, &sample_tee_config(), Platform::Tee);

        // then
        assert_matches!(result, Err(LauncherError::ReservedConfigKey(key)) => {
            assert_eq!(key, "tee");
        });
    }

    #[test]
    fn intercept_config_empty_table_gets_tee_key() {
        // given
        let config = toml::Table::new();

        // when
        let result = intercept_node_config(config, &sample_tee_config(), Platform::Tee).unwrap();

        // then
        assert!(result.contains_key("tee"));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn intercept_config_preserves_all_existing_keys() {
        // given
        let config: toml::Table = toml::from_str(
            r#"
home_dir = "/data"
port = 8080
[nested]
key = "value"
"#,
        )
        .unwrap();

        // when
        let result = intercept_node_config(config, &sample_tee_config(), Platform::Tee).unwrap();

        // then
        assert_eq!(result["home_dir"].as_str(), Some("/data"));
        assert_eq!(result["port"].as_integer(), Some(8080));
        assert_eq!(result["nested"]["key"].as_str(), Some("value"));
        assert!(result.contains_key("tee"));
    }

    #[test]
    fn intercept_config_dstack_tee_config_serializes_correctly() {
        // given
        let config = toml::Table::new();
        let tee = TeeConfig {
            authority: TeeAuthorityConfig::Dstack {
                dstack_endpoint: "/my/socket".to_string(),
            },
            image_hash: sample_digest(),
            latest_allowed_hash_file_path: "/mnt/shared/image-digest.bin".into(),
        };

        // when
        let result = intercept_node_config(config, &tee, Platform::Tee).unwrap();

        // then
        let tee_table = result["tee"].as_table().unwrap();
        let authority = tee_table["authority"].as_table().unwrap();
        assert_eq!(authority["dstack_endpoint"].as_str(), Some("/my/socket"));
    }

    #[test]
    fn intercept_config_local_tee_config_serializes_correctly() {
        // given
        let config = toml::Table::new();
        let tee = TeeConfig {
            authority: TeeAuthorityConfig::Local,
            image_hash: sample_digest(),
            latest_allowed_hash_file_path: "/mnt/shared/image-digest.bin".into(),
        };

        // when
        let result = intercept_node_config(config, &tee, Platform::Tee).unwrap();

        // then — Local variant is a unit variant; just verify the key exists
        assert!(result.contains_key("tee"));
        // re-serialize the whole thing to verify it round-trips
        let toml_str = toml::to_string(&result).unwrap();
        assert!(toml_str.contains("tee"));
    }

    #[test]
    fn intercept_config_image_config_contains_expected_fields() {
        // given
        let config = toml::Table::new();
        let tee = TeeConfig {
            authority: TeeAuthorityConfig::Dstack {
                dstack_endpoint: "/var/run/dstack.sock".to_string(),
            },
            image_hash: digest('b'),
            latest_allowed_hash_file_path: "/some/path".into(),
        };

        // when
        let result = intercept_node_config(config, &tee, Platform::Tee).unwrap();

        // then
        let tee_table = result["tee"].as_table().unwrap();
        assert!(tee_table["image_hash"].as_str().unwrap().contains("bbbb"));
        assert_eq!(
            tee_table["latest_allowed_hash_file_path"].as_str(),
            Some("/some/path")
        );
    }

    #[test]
    fn intercept_config_output_re_serializes_to_valid_toml() {
        // given
        let config: toml::Table = toml::from_str(r#"home_dir = "/data""#).unwrap();

        // when
        let result = intercept_node_config(config, &sample_tee_config(), Platform::Tee).unwrap();
        let toml_str = toml::to_string(&result).unwrap();

        // then — the output can be parsed back
        let reparsed: toml::Table = toml::from_str(&toml_str).unwrap();
        assert!(reparsed.contains_key("tee"));
        assert_eq!(reparsed["home_dir"].as_str(), Some("/data"));
    }

    #[test]
    fn intercept_config_tee_as_non_table_value_is_rejected() {
        // given — tee exists but as a string, not a table
        let config: toml::Table = toml::from_str(r#"tee = "sneaky""#).unwrap();

        // when
        let result = intercept_node_config(config, &sample_tee_config(), Platform::Tee);

        // then — any occupied entry is rejected regardless of value type
        assert_matches!(result, Err(LauncherError::ReservedConfigKey(key)) => {
            assert_eq!(key, "tee");
        });
    }

    #[test]
    fn intercept_config_rejects_gcp_in_tee_mode() {
        // given
        let config: toml::Table = toml::from_str(
            r#"
home_dir = "/data"
[gcp]
keyshare_secret_id = "my-secret"
project_id = "my-project"
"#,
        )
        .unwrap();

        // when
        let result = intercept_node_config(config, &sample_tee_config(), Platform::Tee);

        // then
        assert_matches!(result, Err(LauncherError::TeeRestrictedConfigKey(key)) => {
            assert_eq!(key, "gcp");
        });
    }

    #[test]
    fn intercept_config_allows_gcp_in_nontee_mode() {
        // given
        let config: toml::Table = toml::from_str(
            r#"
home_dir = "/data"
[gcp]
keyshare_secret_id = "my-secret"
project_id = "my-project"
"#,
        )
        .unwrap();

        // when
        let result = intercept_node_config(config, &sample_tee_config(), Platform::NonTee);

        // then
        assert_matches!(result, Ok(table) => {
            assert!(table.contains_key("gcp"));
        });
    }

    // --- validate_image_reference: positive (valid references) ---

    #[test]
    fn valid_docker_hub_simple() {
        validate_image_reference("nearone/mpc-node").unwrap();
    }

    #[test]
    fn valid_docker_hub_with_tag() {
        validate_image_reference("nearone/mpc-node:3.8.1").unwrap();
    }

    #[test]
    fn valid_docker_hub_with_text_tag() {
        validate_image_reference("nearone/mpc-node:testnet-release").unwrap();
    }

    #[test]
    fn valid_ghcr() {
        validate_image_reference("ghcr.io/nearone/mpc-node").unwrap();
    }

    #[test]
    fn valid_ecr_public() {
        validate_image_reference("public.ecr.aws/myalias/mpc-node").unwrap();
    }

    #[test]
    fn valid_google_artifact_registry() {
        validate_image_reference("us-docker.pkg.dev/my-project/my-repo/mpc-node").unwrap();
    }

    #[test]
    fn valid_azure_acr() {
        validate_image_reference("myregistry.azurecr.io/mpc-node").unwrap();
    }

    #[test]
    fn valid_self_hosted_with_port() {
        validate_image_reference("registry.example.com:5000/myproject/mpc-node").unwrap();
    }

    #[test]
    fn valid_self_hosted_with_port_and_tag() {
        validate_image_reference("registry.example.com:5000/myproject/mpc-node:v1.0").unwrap();
    }

    #[test]
    fn valid_simple_name() {
        validate_image_reference("ubuntu").unwrap();
    }

    #[test]
    fn valid_library_image() {
        validate_image_reference("library/alpine").unwrap();
    }

    #[test]
    fn valid_deep_path() {
        validate_image_reference("ghcr.io/org/team/subproject/image").unwrap();
    }

    #[test]
    fn valid_underscore_in_name() {
        validate_image_reference("my_org/my_image").unwrap();
    }

    // --- validate_image_reference: negative (structurally invalid) ---

    #[test]
    fn rejects_empty() {
        assert_matches!(
            validate_image_reference(""),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_trailing_colon() {
        assert_matches!(
            validate_image_reference("nearone/mpc-node:"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_trailing_slash() {
        assert_matches!(
            validate_image_reference("nearone/"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_trailing_dot() {
        assert_matches!(
            validate_image_reference("nearone/mpc-node."),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_double_slash() {
        assert_matches!(
            validate_image_reference("nearone//mpc-node"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_double_colon() {
        assert_matches!(
            validate_image_reference("nearone/mpc-node::tag"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_colon_dot() {
        assert_matches!(
            validate_image_reference("nearone/mpc-node:.tag"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_starting_with_dot() {
        assert_matches!(
            validate_image_reference(".hidden/image"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_starting_with_slash() {
        assert_matches!(
            validate_image_reference("/nearone/mpc-node"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_starting_with_colon() {
        assert_matches!(
            validate_image_reference(":latest"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    // --- validate_image_reference: negative (malicious input) ---

    #[test]
    fn rejects_spaces() {
        assert_matches!(
            validate_image_reference("nearone/mpc node"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_newline_injection() {
        assert_matches!(
            validate_image_reference("nearone/mpc-node\nevil: true"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_yaml_injection_quotes() {
        assert_matches!(
            validate_image_reference("nearone/mpc-node\"; evil"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_shell_metacharacters() {
        assert_matches!(
            validate_image_reference("nearone/mpc-node; rm -rf /"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_backtick_injection() {
        assert_matches!(
            validate_image_reference("nearone/`whoami`"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_dollar_expansion() {
        assert_matches!(
            validate_image_reference("nearone/${USER}"),
            Err(LauncherError::InvalidImageName(_))
        );
    }

    #[test]
    fn rejects_backslash() {
        assert_matches!(
            validate_image_reference("nearone\\mpc-node"),
            Err(LauncherError::InvalidImageName(_))
        );
    }
}
