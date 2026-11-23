use launcher_interface::types::TeeConfig;
use mpc_primitives::hash::GenesisHash;
use near_account_id::AccountId;

use crate::{constants::MPC_HOME_DIR, error::LauncherError, types::Service};

/// Inject the launcher-controlled keys into the user-provided config of the [`Service`] it
/// launches: the `tee` section and the contract id and its chain's genesis hash measured into the
/// launcher compose. For an MPC node it also sets the home directory, so that the node always
/// starts from the chain data already on the disk; a backup service gets it on its command line.
/// Fails if the user config sets any of them to a different value. Equal values are accepted so
/// that a user config written for an older launcher keeps working.
pub fn intercept_service_config(
    service: Service,
    mut service_config: toml::Table,
    tee_config: &TeeConfig,
    mpc_contract_id: &AccountId,
    genesis_hash: &GenesisHash,
) -> Result<toml::Table, LauncherError> {
    insert_reserved(
        &mut service_config,
        &[],
        "tee",
        toml::Value::try_from(tee_config).expect("tee config serializes to TOML"),
    )?;
    let chain_parents: &[&str] = match service {
        Service::MpcNode => {
            insert_reserved(&mut service_config, &[], "home_dir", MPC_HOME_DIR.into())?;
            &["node", "indexer"]
        }
        Service::BackupService => &[],
    };
    insert_reserved(
        &mut service_config,
        chain_parents,
        "mpc_contract_id",
        mpc_contract_id.as_str().into(),
    )?;
    insert_reserved(
        &mut service_config,
        chain_parents,
        "genesis_hash",
        genesis_hash.to_string().into(),
    )?;

    Ok(service_config)
}

fn insert_reserved(
    mut table: &mut toml::Table,
    parents: &[&str],
    key: &str,
    value: toml::Value,
) -> Result<(), LauncherError> {
    let reserved_key = || LauncherError::ReservedConfigKey([parents, &[key]].concat().join("."));
    for parent in parents {
        table = table
            .entry(*parent)
            .or_insert_with(|| toml::Table::new().into())
            .as_table_mut()
            .ok_or_else(reserved_key)?;
    }
    match table.entry(key) {
        toml::map::Entry::Vacant(vacant) => {
            vacant.insert(value);
            Ok(())
        }
        // TODO(#5225): reject equal values too once older launchers are no longer approved
        toml::map::Entry::Occupied(occupied) if *occupied.get() == value => Ok(()),
        toml::map::Entry::Occupied(_) => Err(reserved_key()),
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

    const MPC_CONTRACT_ID: &str = "v1.signer";

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

    fn intercept(
        service: Service,
        config: toml::Table,
        tee_config: &TeeConfig,
    ) -> Result<toml::Table, LauncherError> {
        intercept_service_config(
            service,
            config,
            tee_config,
            &MPC_CONTRACT_ID.parse().unwrap(),
            &GenesisHash::MAINNET,
        )
    }

    #[rstest]
    #[case::mpc_node(
        Service::MpcNode,
        r#"
        port = 8080
        node.indexer.sync_mode = "Latest"
        "#,
        format!(
            r#"
            port = 8080
            home_dir = "/data"
            node.indexer.sync_mode = "Latest"
            node.indexer.mpc_contract_id = "{MPC_CONTRACT_ID}"
            node.indexer.genesis_hash = "{}"
            "#,
            GenesisHash::MAINNET
        )
    )]
    #[case::backup_service(
        Service::BackupService,
        "mpc_node_migration_port = 8079",
        format!(
            r#"
            mpc_node_migration_port = 8079
            mpc_contract_id = "{MPC_CONTRACT_ID}"
            genesis_hash = "{}"
            "#,
            GenesisHash::MAINNET
        )
    )]
    fn intercept_service_config__should_add_the_reserved_keys_and_keep_the_user_config(
        #[case] service: Service,
        #[case] user_config: &str,
        #[case] expected_without_tee: String,
    ) {
        // Given
        let config: toml::Table = toml::from_str(user_config).unwrap();

        // When
        let result = intercept(service, config, &sample_tee_config()).unwrap();

        // Then
        let mut expected: toml::Table = toml::from_str(&expected_without_tee).unwrap();
        expected.insert(
            "tee".into(),
            toml::Value::try_from(sample_tee_config()).unwrap(),
        );
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::tee_table(Service::MpcNode, r#"tee.type = "Local""#, "tee")]
    #[case::tee_value(Service::MpcNode, r#"tee = "sneaky""#, "tee")]
    #[case::home_dir(Service::MpcNode, r#"home_dir = "/tmp""#, "home_dir")]
    #[case::contract_id(
        Service::MpcNode,
        r#"node.indexer.mpc_contract_id = "other.near""#,
        "node.indexer.mpc_contract_id"
    )]
    #[case::genesis_hash(
        Service::MpcNode,
        r#"node.indexer.genesis_hash = "other""#,
        "node.indexer.genesis_hash"
    )]
    #[case::non_table_parent(
        Service::MpcNode,
        r#"node.indexer = "sneaky""#,
        "node.indexer.mpc_contract_id"
    )]
    #[case::backup_service_tee(Service::BackupService, r#"tee.type = "Local""#, "tee")]
    #[case::backup_service_contract_id(
        Service::BackupService,
        r#"mpc_contract_id = "other.near""#,
        "mpc_contract_id"
    )]
    #[case::backup_service_genesis_hash(
        Service::BackupService,
        r#"genesis_hash = "other""#,
        "genesis_hash"
    )]
    fn intercept_service_config__should_reject_a_user_config_that_sets_a_reserved_key(
        #[case] service: Service,
        #[case] user_config: &str,
        #[case] reserved_key: &str,
    ) {
        // Given
        let config: toml::Table = toml::from_str(user_config).unwrap();

        // When
        let result = intercept(service, config, &sample_tee_config());

        // Then
        assert_matches!(result, Err(LauncherError::ReservedConfigKey(key)) if key == reserved_key);
    }

    #[rstest]
    #[case::home_dir(Service::MpcNode, "home_dir", MPC_HOME_DIR)]
    #[case::contract_id(Service::MpcNode, "node.indexer.mpc_contract_id", MPC_CONTRACT_ID)]
    #[case::backup_service_contract_id(Service::BackupService, "mpc_contract_id", MPC_CONTRACT_ID)]
    fn intercept_service_config__should_accept_a_reserved_key_set_to_the_launcher_value(
        #[case] service: Service,
        #[case] reserved_key: &str,
        #[case] launcher_value: &str,
    ) {
        // Given
        let config: toml::Table =
            toml::from_str(&format!(r#"{reserved_key} = "{launcher_value}""#)).unwrap();
        let tee_config = sample_tee_config();

        // When
        let result = intercept(service, config, &tee_config).unwrap();

        // Then
        let without_the_key = intercept(service, toml::Table::new(), &tee_config).unwrap();
        assert_eq!(result, without_the_key);
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
        let result = intercept(Service::MpcNode, config, &tee).unwrap();

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
        let result = intercept(Service::MpcNode, config, &tee).unwrap();

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
        let result = intercept(Service::MpcNode, config, &tee).unwrap();

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
        let config: toml::Table = toml::from_str("port = 8080").unwrap();

        // when
        let result = intercept(Service::MpcNode, config, &sample_tee_config()).unwrap();
        let toml_str = toml::to_string(&result).unwrap();

        // then — the output can be parsed back
        let reparsed: toml::Table = toml::from_str(&toml_str).unwrap();
        assert_eq!(reparsed, result);
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
