use mpc_primitives::hash::{
    GenesisHash, LauncherDockerComposeHash, LauncherImageHash, NodeImageHash,
};
use near_sdk::env;

/// Docker Compose YAML template for the launcher. Compose hashes are derived on-chain as
/// `sha256(template(launcher_hash, mpc_hash, contract_id, genesis_hash))`. Placeholders:
/// - `{{LAUNCHER_IMAGE_HASH}}`: the launcher Docker image hash
/// - `{{DEFAULT_IMAGE_DIGEST_HASH}}`: the MPC node Docker image hash
/// - `{{MPC_CONTRACT_ID}}`: the account id of this contract
/// - `{{NEAR_GENESIS_HASH}}`: the genesis hash of the chain this contract runs on, empty if it
///   has none set
///
/// Attestation binds the launcher to this text only through its hash, so it must leave nothing
/// for Docker Compose to resolve at start-up: no variable substitution, no environment variable
/// without a value, no key such as `env_file` or `build` that makes Compose read guest files
const LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE: &str =
    include_str!("../../assets/launcher_docker_compose.yaml.template");

/// The MPC node template plus a `LAUNCHED_SERVICE` line naming the service for the launcher to
/// start. The line also keeps the compose hashes of the two services apart
const BACKUP_SERVICE_LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE: &str =
    include_str!("../../assets/backup_service_launcher_docker_compose.yaml.template");

#[derive(Clone, Copy)]
pub struct LauncherCompose {
    template: &'static str,
    genesis_hash: Option<GenesisHash>,
}

impl LauncherCompose {
    pub const fn mpc_node(genesis_hash: Option<GenesisHash>) -> Self {
        Self {
            template: LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE,
            genesis_hash,
        }
    }

    pub const fn backup_service(genesis_hash: Option<GenesisHash>) -> Self {
        Self {
            template: BACKUP_SERVICE_LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE,
            genesis_hash,
        }
    }

    /// Fills the template with the [`LauncherImageHash`], the [`NodeImageHash`], this contract's
    /// account id and the genesis hash, and returns the SHA-256 of the result.
    pub fn hash(
        self,
        launcher: &LauncherImageHash,
        image: &NodeImageHash,
    ) -> LauncherDockerComposeHash {
        let filled_yaml = self
            .template
            .replace("{{LAUNCHER_IMAGE_HASH}}", &launcher.as_hex())
            .replace("{{DEFAULT_IMAGE_DIGEST_HASH}}", &image.as_hex())
            .replace("{{MPC_CONTRACT_ID}}", env::current_account_id().as_str())
            .replace(
                "{{NEAR_GENESIS_HASH}}",
                &self.genesis_hash.map_or_default(|hash| hash.to_string()),
            );
        LauncherDockerComposeHash::from(env::sha256_array(filled_yaml))
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use near_sdk::{test_utils::VMContextBuilder, testing_env};
    use serde_yaml::Value;

    use super::{GenesisHash, LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE, LauncherCompose};
    use crate::{
        primitives::test_utils::bogus_genesis_hash,
        tee::test_utils::{MPC_NODE_COMPOSE, dummy_code_hash, dummy_launcher_hash},
    };

    #[test]
    fn test_compose_hash_uses_both_hashes() {
        let launcher_1 = dummy_launcher_hash(1);
        let launcher_2 = dummy_launcher_hash(2);
        let mpc_hash = dummy_code_hash(10);

        let compose_1 = MPC_NODE_COMPOSE.hash(&launcher_1, &mpc_hash);
        let compose_2 = MPC_NODE_COMPOSE.hash(&launcher_2, &mpc_hash);

        // Different launcher hashes should produce different compose hashes
        assert_ne!(compose_1, compose_2);
    }

    #[test]
    fn launcher_compose__should_bind_the_compose_to_the_contract_account_and_its_chain() {
        // Given
        let launcher = dummy_launcher_hash(1);
        let mpc_hash = dummy_code_hash(10);
        let contract_id = "v1.signer";
        let genesis_hash = bogus_genesis_hash();
        let compose_hash_for = |account: &str, genesis_hash: Option<GenesisHash>| {
            testing_env!(
                VMContextBuilder::new()
                    .current_account_id(account.parse().unwrap())
                    .build()
            );
            LauncherCompose::mpc_node(genesis_hash).hash(&launcher, &mpc_hash)
        };

        // When
        let compose_hash = compose_hash_for(contract_id, Some(genesis_hash));
        let compose_hash_of_other_contract = compose_hash_for("other.near", Some(genesis_hash));
        let compose_hash_on_other_chain =
            compose_hash_for(contract_id, Some(GenesisHash::from([2; 32])));
        let compose_hash_on_any_chain = compose_hash_for(contract_id, None);

        // Then
        assert_ne!(compose_hash, compose_hash_of_other_contract);
        assert_ne!(compose_hash, compose_hash_on_other_chain);
        assert_ne!(compose_hash, compose_hash_on_any_chain);
    }

    #[test]
    fn launcher_compose__should_differ_between_services() {
        // Given
        let launcher = dummy_launcher_hash(1);
        let image = dummy_code_hash(10);
        let genesis_hash = Some(bogus_genesis_hash());

        // When
        let mpc_node_compose_hash = LauncherCompose::mpc_node(genesis_hash).hash(&launcher, &image);
        let backup_service_compose_hash =
            LauncherCompose::backup_service(genesis_hash).hash(&launcher, &image);

        // Then
        assert_ne!(mpc_node_compose_hash, backup_service_compose_hash);
    }

    #[test]
    fn backup_service_template__should_add_only_the_service_line_to_the_mpc_node_template() {
        // Given
        let platform_line = "      - PLATFORM=TEE\n";
        let mpc_node_template = LauncherCompose::mpc_node(None).template;

        // When
        let backup_service_template = LauncherCompose::backup_service(None).template;

        // Then
        assert_eq!(
            backup_service_template,
            mpc_node_template.replacen(
                platform_line,
                &format!("{platform_line}      - LAUNCHED_SERVICE=backup-service\n"),
                1,
            )
        );
    }

    fn parsed_template() -> Value {
        serde_yaml::from_str(LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE).unwrap()
    }

    fn key_paths(value: &Value, parent: &str) -> Vec<String> {
        match value {
            Value::Mapping(mapping) => mapping
                .iter()
                .flat_map(|(key, value)| {
                    let path = format!("{parent}{}", key.as_str().unwrap());
                    let nested_paths = key_paths(value, &format!("{path}."));
                    std::iter::once(path).chain(nested_paths)
                })
                .collect(),
            Value::Sequence(items) => items
                .iter()
                .flat_map(|item| key_paths(item, parent))
                .collect(),
            Value::Tagged(tagged) => key_paths(&tagged.value, parent),
            _ => Vec::new(),
        }
    }

    #[test]
    fn launcher_docker_compose_template__should_not_use_variable_substitution() {
        // Given
        let template = LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE;

        // When
        let lines_with_substitution: Vec<&str> =
            template.lines().filter(|line| line.contains('$')).collect();

        // Then
        assert_eq!(lines_with_substitution, Vec::<&str>::new());
    }

    #[test]
    fn launcher_docker_compose_template__should_only_use_reviewed_keys() {
        // Given
        let template = parsed_template();

        // When
        let keys = key_paths(&template, "");

        // Then
        assert_eq!(
            keys,
            [
                "version",
                "services",
                "services.launcher",
                "services.launcher.image",
                "services.launcher.container_name",
                "services.launcher.environment",
                "services.launcher.volumes",
                "services.launcher.devices",
                "services.launcher.security_opt",
                "services.launcher.read_only",
                "services.launcher.tmpfs",
                "volumes",
                "volumes.shared-volume",
                "volumes.shared-volume.name",
            ]
        );
    }

    #[test]
    fn launcher_docker_compose_template__should_not_inherit_environment_variables_from_compose() {
        // Given
        let template = parsed_template();

        // When
        let inherited_variables: Vec<&str> = template["services"]["launcher"]["environment"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|entry| entry.as_str().unwrap())
            .filter(|entry| !entry.contains('='))
            .collect();

        // Then
        assert_eq!(inherited_variables, Vec::<&str>::new());
    }
}
