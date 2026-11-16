use launcher_interface::types::TeeConfig;

use crate::error::LauncherError;

/// Inject launcher-controlled config section (`tee`) into the user-provided
/// MPC node config table.  Returns an error if the user config already
/// contains a reserved key.
pub fn intercept_node_config(
    mut node_config: toml::Table,
    tee_config: &TeeConfig,
) -> Result<toml::Table, LauncherError> {
    insert_reserved(
        &mut node_config,
        "tee",
        toml::Value::try_from(tee_config).expect("tee config serializes to TOML"),
    )?;

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
#[expect(non_snake_case)]
mod tests {
    use launcher_interface::types::{DockerSha256Digest, TeeAuthorityConfig, TeeConfig};
    use rstest::rstest;
    use std::assert_matches;

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
                dstack_endpoint: "/var/run/dstack.sock".into(),
            },
            image_hash: sample_digest(),
            latest_allowed_hash_file_path: "/mnt/shared/image-digest.bin".into(),
        }
    }

    #[rstest]
    #[case::injects_tee_config_into_populated_table(r#"home_dir = "/data""#)]
    #[case::empty_table_gets_tee_key("")]
    fn intercept_node_config__should_add_only_tee_key(#[case] config_toml: &str) {
        // Given
        let config: toml::Table = toml::from_str(config_toml).unwrap();
        let expected = config.clone();

        // When
        let mut result = intercept_node_config(config, &sample_tee_config()).unwrap();

        // Then
        assert!(result.remove("tee").is_some());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::user_provided_tee_table("[tee]\ntype = \"Local\"\n")]
    #[case::tee_as_non_table_value(r#"tee = "sneaky""#)]
    fn intercept_node_config__should_reject_existing_tee_key(#[case] config_toml: &str) {
        // Given
        let config: toml::Table = toml::from_str(config_toml).unwrap();

        // When
        let result = intercept_node_config(config, &sample_tee_config());

        // Then
        assert_matches!(result, Err(LauncherError::ReservedConfigKey(key)) if key == "tee");
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
        let result = intercept_node_config(config, &sample_tee_config()).unwrap();

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
                dstack_endpoint: "/my/socket".into(),
            },
            image_hash: sample_digest(),
            latest_allowed_hash_file_path: "/mnt/shared/image-digest.bin".into(),
        };

        // when
        let result = intercept_node_config(config, &tee).unwrap();

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
        let result = intercept_node_config(config, &tee).unwrap();

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
                dstack_endpoint: "/var/run/dstack.sock".into(),
            },
            image_hash: digest('b'),
            latest_allowed_hash_file_path: "/some/path".into(),
        };

        // when
        let result = intercept_node_config(config, &tee).unwrap();

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
        let result = intercept_node_config(config, &sample_tee_config()).unwrap();
        let toml_str = toml::to_string(&result).unwrap();

        // then — the output can be parsed back
        let reparsed: toml::Table = toml::from_str(&toml_str).unwrap();
        assert!(reparsed.contains_key("tee"));
        assert_eq!(reparsed["home_dir"].as_str(), Some("/data"));
    }

    #[rstest]
    #[case::docker_hub_simple("nearone/mpc-node")]
    #[case::docker_hub_with_tag("nearone/mpc-node:3.8.1")]
    #[case::docker_hub_with_text_tag("nearone/mpc-node:testnet-release")]
    #[case::ghcr("ghcr.io/nearone/mpc-node")]
    #[case::ecr_public("public.ecr.aws/myalias/mpc-node")]
    #[case::google_artifact_registry("us-docker.pkg.dev/my-project/my-repo/mpc-node")]
    #[case::azure_acr("myregistry.azurecr.io/mpc-node")]
    #[case::self_hosted_with_port("registry.example.com:5000/myproject/mpc-node")]
    #[case::self_hosted_with_port_and_tag("registry.example.com:5000/myproject/mpc-node:v1.0")]
    #[case::simple_name("ubuntu")]
    #[case::library_image("library/alpine")]
    #[case::deep_path("ghcr.io/org/team/subproject/image")]
    #[case::underscore_in_name("my_org/my_image")]
    fn validate_image_reference__should_accept_valid_reference(#[case] image_ref: &str) {
        // When
        let result = validate_image_reference(image_ref);

        // Then
        result.unwrap();
    }

    #[rstest]
    #[case::empty("")]
    #[case::trailing_colon("nearone/mpc-node:")]
    #[case::trailing_slash("nearone/")]
    #[case::trailing_dot("nearone/mpc-node.")]
    #[case::double_slash("nearone//mpc-node")]
    #[case::double_colon("nearone/mpc-node::tag")]
    #[case::colon_dot("nearone/mpc-node:.tag")]
    #[case::starting_with_dot(".hidden/image")]
    #[case::starting_with_slash("/nearone/mpc-node")]
    #[case::starting_with_colon(":latest")]
    #[case::spaces("nearone/mpc node")]
    #[case::newline_injection("nearone/mpc-node\nevil: true")]
    #[case::yaml_injection_quotes("nearone/mpc-node\"; evil")]
    #[case::shell_metacharacters("nearone/mpc-node; rm -rf /")]
    #[case::backtick_injection("nearone/`whoami`")]
    #[case::dollar_expansion("nearone/${USER}")]
    #[case::backslash("nearone\\mpc-node")]
    fn validate_image_reference__should_reject_invalid_reference(#[case] image_ref: &str) {
        // When
        let result = validate_image_reference(image_ref);

        // Then
        assert_matches!(result, Err(LauncherError::InvalidImageName(_)));
    }
}
