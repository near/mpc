use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use launcher_interface::types::DockerSha256Digest;
use url::Host;

use clap::{Parser, ValueEnum};
use near_mpc_bounded_collections::NonEmptyVec;
use serde::{Deserialize, Serialize};

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

/// Typed representation of the dstack user config file (`/tapp/user_config`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub launcher_config: LauncherConfig,
    /// Opaque MPC node configuration table.
    /// The launcher does not interpret these fields — they are re-serialized
    /// to a TOML string, written to a file on disk, and mounted into the
    /// container for the MPC binary to consume via `start-with-config-file`.
    pub mpc_node_config: toml::Table,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LauncherConfig {
    /// Docker image tags to search. Set via `image_tags` in TOML, e.g. `image_tags = ["3.7.0"]`.
    pub image_tags: NonEmptyVec<String>,
    /// Docker image name. Set via `image_name` in TOML, e.g. `"nearone/mpc-node"`.
    pub image_name: String,
    /// Docker registry hostname. Set via `registry` in TOML, e.g. `"registry.hub.docker.com"`.
    pub registry: String,
    /// Per-request timeout for registry API calls, in seconds. Set via `rpc_request_timeout_secs`.
    pub rpc_request_timeout_secs: u64,
    /// Delay between registry API retries, in seconds. Set via `rpc_request_interval_secs`.
    pub rpc_request_interval_secs: u64,
    /// Maximum number of registry API retry attempts. Set via `rpc_max_attempts`.
    pub rpc_max_attempts: u32,
    /// Optional digest override (`sha256:...`) that bypasses the approved list selection.
    /// Must still appear in the approved hashes file if present. Set via `mpc_hash_override`.
    pub mpc_hash_override: Option<DockerSha256Digest>,
    pub port_mappings: Vec<PortMapping>,
}

/// A `--add-host` entry: `hostname:IPv4`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEntry {
    pub hostname: Host<String>,
    pub ip: Ipv4Addr,
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
mod tests {
    use assert_matches::assert_matches;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU16;

    use super::*;

    // --- HostEntry deserialization ---

    #[test]
    fn host_entry_valid_deserialization() {
        // given
        let json = serde_json::json!({"hostname": {"Domain": "node.local"}, "ip": "192.168.1.1"});

        // when
        let result = serde_json::from_value::<HostEntry>(json);

        // then
        assert_matches!(result, Ok(entry) => {
            assert_eq!(entry.ip, Ipv4Addr::new(192, 168, 1, 1));
        });
    }

    #[test]
    fn host_entry_rejects_invalid_ip() {
        // given
        let json = serde_json::json!({"hostname": {"Domain": "node.local"}, "ip": "not-an-ip"});

        // when
        let result = serde_json::from_value::<HostEntry>(json);

        // then
        assert_matches!(result, Err(e) => {
            assert!(e.to_string().contains("invalid"), "expected IP parse error, got: {e}");
        });
    }

    #[test]
    fn host_entry_rejects_plain_string_as_hostname() {
        // given - url::Host requires tagged variant, plain string is rejected
        let json = serde_json::json!({"hostname": "node.local", "ip": "192.168.1.1"});

        // when
        let result = serde_json::from_value::<HostEntry>(json);

        // then
        assert_matches!(result, Err(_));
    }

    #[test]
    fn host_entry_rejects_injection_string_as_hostname() {
        // given
        let json = serde_json::json!({"hostname": "--env LD_PRELOAD=hack.so", "ip": "192.168.1.1"});

        // when
        let result = serde_json::from_value::<HostEntry>(json);

        // then
        assert_matches!(result, Err(_));
    }

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
        assert_matches!(result, Err(e) => {
            assert!(e.to_string().contains("nonzero"), "expected nonzero port error, got: {e}");
        });
    }

    #[test]
    fn port_mapping_rejects_out_of_range_port() {
        // given
        let json = serde_json::json!({"host": 65536, "container": 11780});

        // when
        let result = serde_json::from_value::<PortMapping>(json);

        // then
        assert_matches!(result, Err(e) => {
            assert!(e.to_string().contains("u16"), "expected u16 range error, got: {e}");
        });
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
image_tags = ["tag1"]
image_name = "nearone/mpc-node"
registry = "registry.hub.docker.com"
rpc_request_timeout_secs = 10
rpc_request_interval_secs = 1
rpc_max_attempts = 20

port_mappings = [{ host = 11780, container = 11780 }]

[mpc_node_config]
home_dir = "/data"
some_opaque_field = true
"#;

        // when
        let result = toml::from_str::<Config>(toml_str);

        // then
        assert_matches!(result, Ok(config) => {
            assert_eq!(config.launcher_config.image_name, "nearone/mpc-node");
            assert_eq!(config.mpc_node_config["home_dir"].as_str(), Some("/data"));
            assert_eq!(config.mpc_node_config["some_opaque_field"].as_bool(), Some(true));
        });
    }

    #[test]
    fn config_mpc_config_round_trips_to_toml_string() {
        // given
        let toml_str = r#"
[launcher_config]
image_tags = ["tag1"]
image_name = "nearone/mpc-node"
registry = "registry.hub.docker.com"
rpc_request_timeout_secs = 10
rpc_request_interval_secs = 1
rpc_max_attempts = 20

port_mappings = [{ host = 11780, container = 11780 }]

[mpc_node_config]
home_dir = "/data"
arbitrary_key = "arbitrary_value"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();

        // when — re-serialize the opaque table (what the launcher writes to disk)
        let serialized = toml::to_string(&config.mpc_node_config).unwrap();

        // then
        assert!(serialized.contains("home_dir"));
        assert!(serialized.contains("arbitrary_key"));
    }

    #[test]
    fn config_rejects_missing_required_field() {
        // given - mpc_node_config is missing
        let toml_str = r#"
[launcher_config]
image_tags = ["tag1"]
image_name = "nearone/mpc-node"
registry = "registry.hub.docker.com"
rpc_request_timeout_secs = 10
rpc_request_interval_secs = 1
rpc_max_attempts = 20

port_mappings = []
"#;

        // when
        let result = toml::from_str::<Config>(toml_str);

        // then
        assert_matches!(result, Err(e) => {
            assert!(e.to_string().contains("mpc_node_config"), "expected missing field error, got: {e}");
        });
    }
}
