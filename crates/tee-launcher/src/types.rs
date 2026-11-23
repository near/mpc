use std::num::NonZeroU16;

use launcher_interface::types::DockerSha256Digest;
use mpc_primitives::hash::GenesisHash;
use near_account_id::AccountId;

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::{
    constants::{BACKUP_SERVICE_CONFIG_SHARED_PATH, MPC_CONFIG_SHARED_PATH, MPC_HOME_DIR},
    error::LauncherError,
};

/// CLI arguments parsed from environment variables via clap.
#[derive(Parser, Debug)]
#[command(name = "tee-launcher")]
pub struct CliArgs {
    /// Platform mode: TEE or NONTEE
    #[arg(long, env = "PLATFORM")]
    pub platform: Platform,

    #[arg(long, env = "DOCKER_CONTENT_TRUST")]
    // ensure that `docker_content_trust` is enabled.
    docker_content_trust: DockerContentTrust,

    /// Fallback image digest when the approved-hashes file is absent
    #[arg(long, env = "DEFAULT_IMAGE_DIGEST")]
    pub default_image_digest: DockerSha256Digest,

    /// Account id of the MPC contract the node serves
    #[arg(long, env = "MPC_CONTRACT_ID")]
    pub mpc_contract_id: AccountId,

    /// Genesis hash of the chain the MPC contract runs on
    #[arg(long, env = "NEAR_GENESIS_HASH")]
    pub near_genesis_hash: GenesisHash,

    /// Service to launch: `mpc-node` or `backup-service`
    #[arg(long, env = "LAUNCHED_SERVICE", value_enum, default_value_t)]
    pub launched_service: Service,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DockerContentTrust {
    #[value(name = "1")]
    Enabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Platform {
    #[value(name = "TEE")]
    Tee,
    #[value(name = "NONTEE")]
    NonTee,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum Service {
    #[default]
    MpcNode,
    BackupService,
}

impl Service {
    pub fn container_name(self) -> &'static str {
        match self {
            Self::MpcNode => "mpc-node",
            Self::BackupService => "backup-service",
        }
    }

    /// Where the launcher writes the service's config, on the volume both containers mount
    pub fn config_path(self) -> &'static str {
        match self {
            Self::MpcNode => MPC_CONFIG_SHARED_PATH,
            Self::BackupService => BACKUP_SERVICE_CONFIG_SHARED_PATH,
        }
    }

    pub fn command(self) -> &'static [&'static str] {
        match self {
            Self::MpcNode => &[
                "/app/mpc-node",
                "start-with-config-file",
                MPC_CONFIG_SHARED_PATH,
            ],
            Self::BackupService => &[
                "/app/backup-cli",
                "--home-dir",
                MPC_HOME_DIR,
                "start-with-config-file",
                BACKUP_SERVICE_CONFIG_SHARED_PATH,
            ],
        }
    }
}

/// Typed representation of the dstack user config file (`/tapp/user_config`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub launcher_config: LauncherConfig,
    /// MPC node configuration table, required to launch an MPC node. The launcher adds its
    /// reserved keys, serializes the result to TOML and mounts it into the container for the MPC
    /// node to read on startup.
    pub mpc_node_config: Option<toml::Table>,
    /// Backup service configuration table, required to launch a backup service. The launcher
    /// handles it as it does [`Config::mpc_node_config`].
    pub backup_service_config: Option<toml::Table>,
}

impl Config {
    /// Splits off the configuration table of the [`Service`] to launch.
    pub fn into_parts(
        self,
        service: Service,
    ) -> Result<(LauncherConfig, toml::Table), LauncherError> {
        let service_config = match service {
            Service::MpcNode => self.mpc_node_config,
            Service::BackupService => self.backup_service_config,
        };
        let service_config = service_config.ok_or(LauncherError::MissingServiceConfig(service))?;
        Ok((self.launcher_config, service_config))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LauncherConfig {
    /// Docker image reference: `[registry[:port]/]name[:tag]`.
    /// A tag can be included to identify the configured version
    /// (e.g., `"nearone/mpc-node:testnet-release"`), but the manifest digest
    /// from the approved hashes file determines the actual image pulled.
    /// Include registry prefix for non-Docker Hub registries.
    /// Examples: `"nearone/mpc-node"`, `"nearone/mpc-node:3.8.1"`,
    /// `"ghcr.io/nearone/mpc-node"`.
    pub image_reference: String,
    /// Maximum number of retries for `docker pull`. Defaults to 5.
    #[serde(default = "default_pull_max_retries")]
    pub pull_max_retries: usize,
    /// Initial delay between pull retries in seconds (exponential backoff base). Defaults to 2.
    #[serde(default = "default_pull_retry_interval_secs")]
    pub pull_retry_interval_secs: u64,
    /// Maximum delay between pull retries in seconds (backoff cap). Defaults to 60.
    #[serde(default = "default_pull_max_delay_secs")]
    pub pull_max_delay_secs: u64,
    /// Optional digest override (`sha256:...`) that bypasses the approved list selection.
    /// Must still appear in the approved hashes file if present. Set via `mpc_hash_override`.
    pub mpc_hash_override: Option<DockerSha256Digest>,
    pub port_mappings: Vec<PortMapping>,
}

fn default_pull_max_retries() -> usize {
    5
}

fn default_pull_max_delay_secs() -> u64 {
    60
}

fn default_pull_retry_interval_secs() -> u64 {
    2
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapping {
    pub host: NonZeroU16,
    pub container: NonZeroU16,
}

impl PortMapping {
    /// Returns e.g. `"11780:11780"` for use in docker-compose port lists.
    pub fn docker_compose_value(&self) -> String {
        format!("{}:{}", self.host, self.container)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::{assert_matches, num::NonZeroU16};

    use rstest::rstest;

    use super::*;

    // --- PortMapping deserialization ---

    #[test]
    fn port_mapping_valid_deserialization() {
        // given
        let json = serde_json::json!({"host": 11780, "container": 11780});

        // when
        let result = serde_json::from_value::<PortMapping>(json);

        // then
        assert_matches!(result, Ok(_));
    }

    #[test]
    fn port_mapping_rejects_zero_port() {
        // given
        let json = serde_json::json!({"host": 0, "container": 11780});

        // when
        let result = serde_json::from_value::<PortMapping>(json);

        // then
        assert_matches!(result, Err(e) if e.to_string().contains("nonzero"));
    }

    #[test]
    fn port_mapping_rejects_out_of_range_port() {
        // given
        let json = serde_json::json!({"host": 65536, "container": 11780});

        // when
        let result = serde_json::from_value::<PortMapping>(json);

        // then
        assert_matches!(result, Err(e) if e.to_string().contains("u16"));
    }

    // --- docker_compose_value output format ---

    #[test]
    fn port_mapping_docker_compose_value() {
        // given
        let mapping = PortMapping {
            host: NonZeroU16::new(11780).unwrap(),
            container: NonZeroU16::new(11780).unwrap(),
        };

        // when
        let value = mapping.docker_compose_value();

        // then
        assert_eq!(value, "11780:11780");
    }

    // --- Config full deserialization (TOML) ---

    #[test]
    fn config_deserializes_valid_toml() {
        // given
        let toml_str = r#"
[launcher_config]
image_reference = "nearone/mpc-node"
port_mappings = [{ host = 11780, container = 11780 }]

[mpc_node_config]
some_opaque_field = true
"#;

        // when
        let result = toml::from_str::<Config>(toml_str);

        // then
        let config = result.unwrap();
        assert_eq!(config.launcher_config.image_reference, "nearone/mpc-node");
        assert_eq!(
            config.mpc_node_config.unwrap()["some_opaque_field"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn config_deserializes_with_registry_prefix() {
        // given
        let toml_str = r#"
[launcher_config]
image_reference = "ghcr.io/nearone/mpc-node"
port_mappings = []

[mpc_node_config]
"#;

        // when
        let result = toml::from_str::<Config>(toml_str);

        // then
        assert_eq!(
            result.unwrap().launcher_config.image_reference,
            "ghcr.io/nearone/mpc-node"
        );
    }

    #[test]
    fn config_mpc_config_round_trips_to_toml_string() {
        // given
        let toml_str = r#"
[launcher_config]
image_reference = "nearone/mpc-node"
port_mappings = [{ host = 11780, container = 11780 }]

[mpc_node_config]
arbitrary_key = "arbitrary_value"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();

        // when — re-serialize the opaque table (what the launcher writes to disk)
        let serialized = toml::to_string(&config.mpc_node_config.unwrap()).unwrap();

        // then
        assert!(serialized.contains("arbitrary_key"));
    }

    #[rstest]
    #[case::mpc_node(Service::MpcNode, "[backup_service_config]")]
    #[case::backup_service(Service::BackupService, "[mpc_node_config]")]
    fn config_into_parts__should_require_the_config_of_the_launched_service(
        #[case] service: Service,
        #[case] other_service_config: &str,
    ) {
        // Given
        let config: Config = toml::from_str(&format!(
            r#"
[launcher_config]
image_reference = "nearone/mpc-node"
port_mappings = []

{other_service_config}
"#
        ))
        .unwrap();

        // When
        let result = config.into_parts(service);

        // Then
        assert_matches!(result, Err(LauncherError::MissingServiceConfig(missing)) if missing == service);
    }

    #[rstest]
    #[case::unset(&[], Service::MpcNode)]
    #[case::backup_service(&["--launched-service", "backup-service"], Service::BackupService)]
    fn cli_args__should_launch_the_mpc_node_unless_the_backup_service_is_selected(
        #[case] launched_service_args: &[&str],
        #[case] expected: Service,
    ) {
        // Given
        let args = [
            "tee-launcher",
            "--platform",
            "TEE",
            "--docker-content-trust",
            "1",
            "--default-image-digest",
            &format!("sha256:{}", "a".repeat(64)),
            "--mpc-contract-id",
            "v1.signer",
            "--near-genesis-hash",
            &GenesisHash::MAINNET.to_string(),
        ];

        // When
        let cli_args = CliArgs::try_parse_from(args.iter().chain(launched_service_args)).unwrap();

        // Then
        assert_eq!(cli_args.launched_service, expected);
    }
}
