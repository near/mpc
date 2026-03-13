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
    pub docker_command_config: DockerLaunchFlags,
    /// Inline MPC node config content (opaque to the launcher).
    /// Written to a temporary file on disk, mounted into the container,
    /// and passed via `start-with-config-file <path>` to the MPC binary.
    pub mpc_config_content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LauncherConfig {
    /// Docker image tags to search (from `MPC_IMAGE_TAGS`, comma-separated).
    pub image_tags: NonEmptyVec<String>,
    /// Docker image name (from `MPC_IMAGE_NAME`).
    pub image_name: String,
    /// Docker registry (from `MPC_REGISTRY`).
    pub registry: String,
    /// Per-request timeout for registry RPC calls (from `RPC_REQUEST_TIMEOUT_SECS`).
    pub rpc_request_timeout_secs: u64,
    /// Delay between registry RPC retries (from `RPC_REQUEST_INTERVAL_SECS`).
    pub rpc_request_interval_secs: u64,
    /// Maximum registry RPC attempts (from `RPC_MAX_ATTEMPTS`).
    pub rpc_max_attempts: u32,
    /// Optional hash override that bypasses registry lookup (from `MPC_HASH_OVERRIDE`).
    pub mpc_hash_override: Option<DockerSha256Digest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerLaunchFlags {
    pub port_mappings: PortMappings,
}

/// A `--add-host` entry: `hostname:IPv4`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEntry {
    pub hostname: Host<String>,
    pub ip: Ipv4Addr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMappings {
    pub ports: Vec<PortMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapping {
    pub(crate) src: NonZeroU16,
    pub(crate) dst: NonZeroU16,
}

impl PortMapping {
    /// Returns e.g. `"11780:11780"` for use in docker-compose port lists.
    pub fn docker_compose_value(&self) -> String {
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

    // --- Config full deserialization ---

    #[test]
    fn config_deserializes_valid_json() {
        // given
        let json = serde_json::json!({
            "launcher_config": {
                "image_tags": ["tag1"],
                "image_name": "nearone/mpc-node",
                "registry": "registry.hub.docker.com",
                "rpc_request_timeout_secs": 10,
                "rpc_request_interval_secs": 1,
                "rpc_max_attempts": 20,
                "mpc_hash_override": null
            },
            "docker_command_config": {
                "port_mappings": {"ports": [{"src": 11780, "dst": 11780}]}
            },
            "mpc_config_file": "[some_config = true]"
        });

        // when
        let result = serde_json::from_value::<Config>(json);

        // then
        assert_matches!(result, Ok(config) => {
            assert_eq!(config.launcher_config.image_name, "nearone/mpc-node");
            assert_eq!(config.mpc_config_content, "[some_config = true]");
        });
    }

    #[test]
    fn config_rejects_missing_required_field() {
        // given - mpc_config_file is missing
        let json = serde_json::json!({
            "launcher_config": {
                "image_tags": ["tag1"],
                "image_name": "nearone/mpc-node",
                "registry": "registry.hub.docker.com",
                "rpc_request_timeout_secs": 10,
                "rpc_request_interval_secs": 1,
                "rpc_max_attempts": 20,
                "mpc_hash_override": null
            },
            "docker_command_config": {
                "port_mappings": {"ports": []}
            }
        });

        // when
        let result = serde_json::from_value::<Config>(json);

        // then
        assert_matches!(result, Err(_));
    }
}
