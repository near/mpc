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
pub(crate) struct CliArgs {
    /// Platform mode: TEE or NONTEE
    #[arg(long, env = "PLATFORM")]
    pub(crate) platform: Platform,

    #[arg(long, env = "DOCKER_CONTENT_TRUST")]
    // ensure that `docker_content_trust` is enabled.
    docker_content_trust: DockerContentTrust,

    /// Fallback image digest when the approved-hashes file is absent
    #[arg(long, env = "DEFAULT_IMAGE_DIGEST")]
    pub(crate) default_image_digest: DockerSha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DockerContentTrust {
    #[value(name = "1")]
    Enabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Platform {
    #[value(name = "TEE")]
    Tee,
    #[value(name = "NONTEE")]
    NonTee,
}

/// Typed representation of the dstack user config file (`/tapp/user_config`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Config {
    pub(crate) launcher_config: LauncherConfig,
    /// Opaque MPC node configuration table.
    /// The launcher does not interpret these fields — they are re-serialized
    /// to a TOML string, written to a file on disk, and mounted into the
    /// container for the MPC binary to consume via `start-with-config-file`.
    pub(crate) mpc_config: toml::Table,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LauncherConfig {
    /// Docker image tags to search (from `MPC_IMAGE_TAGS`, comma-separated).
    pub(crate) image_tags: NonEmptyVec<String>,
    /// Docker image name (from `MPC_IMAGE_NAME`).
    pub(crate) image_name: String,
    /// Docker registry (from `MPC_REGISTRY`).
    pub(crate) registry: String,
    /// Per-request timeout for registry RPC calls (from `RPC_REQUEST_TIMEOUT_SECS`).
    pub(crate) rpc_request_timeout_secs: u64,
    /// Delay between registry RPC retries (from `RPC_REQUEST_INTERVAL_SECS`).
    pub(crate) rpc_request_interval_secs: u64,
    /// Maximum registry RPC attempts (from `RPC_MAX_ATTEMPTS`).
    pub(crate) rpc_max_attempts: u32,
    /// Optional hash override that bypasses registry lookup (from `MPC_HASH_OVERRIDE`).
    pub(crate) mpc_hash_override: Option<DockerSha256Digest>,
    pub(crate) port_mappings: Vec<PortMapping>,
}

/// A `--add-host` entry: `hostname:IPv4`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HostEntry {
    pub(crate) hostname: Host<String>,
    pub(crate) ip: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PortMapping {
    pub(crate) src: NonZeroU16,
    pub(crate) dst: NonZeroU16,
}

impl PortMapping {
    /// Returns e.g. `"11780:11780"` for use in docker-compose port lists.
    pub(crate) fn docker_compose_value(&self) -> String {
        format!("{}:{}", self.src, self.dst)
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
        assert_matches!(result, Err(_));
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
        let json = serde_json::json!({"src": 11780, "dst": 11780});

        // when
        let result = serde_json::from_value::<PortMapping>(json);

        // then
        assert_matches!(result, Ok(_));
    }

    #[test]
    fn port_mapping_rejects_zero_port() {
        // given
        let json = serde_json::json!({"src": 0, "dst": 11780});

        // when
        let result = serde_json::from_value::<PortMapping>(json);

        // then
        assert_matches!(result, Err(_));
    }

    #[test]
    fn port_mapping_rejects_out_of_range_port() {
        // given
        let json = serde_json::json!({"src": 65536, "dst": 11780});

        // when
        let result = serde_json::from_value::<PortMapping>(json);

        // then
        assert_matches!(result, Err(_));
    }

    // --- docker_compose_value output format ---

    #[test]
    fn port_mapping_docker_compose_value() {
        // given
        let mapping = PortMapping {
            src: NonZeroU16::new(11780).unwrap(),
            dst: NonZeroU16::new(11780).unwrap(),
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

port_mappings = [{ src = 11780, dst = 11780 }]

[mpc_config]
home_dir = "/data"
some_opaque_field = true
"#;

        // when
        let result = toml::from_str::<Config>(toml_str);

        // then
        assert_matches!(result, Ok(config) => {
            assert_eq!(config.launcher_config.image_name, "nearone/mpc-node");
            assert_eq!(config.mpc_config["home_dir"].as_str(), Some("/data"));
            assert_eq!(config.mpc_config["some_opaque_field"].as_bool(), Some(true));
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

port_mappings = [{ src = 11780, dst = 11780 }]

[mpc_config]
home_dir = "/data"
arbitrary_key = "arbitrary_value"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();

        // when — re-serialize the opaque table (what the launcher writes to disk)
        let serialized = toml::to_string(&config.mpc_config).unwrap();

        // then
        assert!(serialized.contains("home_dir"));
        assert!(serialized.contains("arbitrary_key"));
    }

    #[test]
    fn config_rejects_missing_required_field() {
        // given - mpc_config is missing
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
        assert_matches!(result, Err(_));
    }
}
