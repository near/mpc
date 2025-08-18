use alloc::{string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Deref, From};
use serde::{Deserialize, Serialize};

/// Helper struct to deserialize the `app_compose` JSON from TCB info. This is a workaround due to
/// current limitations in the Dstack SDK.
///
/// See: https://github.com/Dstack-TEE/dstack/issues/267
#[derive(Debug, Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
pub struct AppCompose {
    pub manifest_version: u32,
    pub name: String,
    pub runner: String,
    pub docker_compose_file: DockerComposeString,
    pub kms_enabled: bool,
    pub tproxy_enabled: Option<bool>,
    pub gateway_enabled: Option<bool>,
    pub public_logs: bool,
    pub public_sysinfo: bool,
    pub local_key_provider_enabled: bool,
    pub key_provider_id: Option<String>,
    pub allowed_envs: Vec<String>,
    pub no_instance_id: bool,
    pub secure_time: Option<bool>,
    pub pre_launch_script: Option<String>,
    // The following fields that don't have any security implication are omitted:
    //
    // - docker_config: JsonValue,
    // - public_tcbinfo: bool,
}

/// A type that contains a docker compose the contents of a docker compose file as
/// a string. For example the docker compose file below can be read as a string and initialize this type.
///
/// This type does currently not do any validation of the string
#[derive(Debug, Deserialize, Serialize, BorshSerialize, BorshDeserialize, From, Deref)]
pub struct DockerComposeString(String);
