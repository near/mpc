use alloc::{string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Deref, From};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Helper struct to deserialize the `app_compose` JSON from TCB info. This is a workaround due to
/// current limitations in the Dstack SDK.
///
/// See: <https://github.com/Dstack-TEE/dstack/issues/267>
///
/// `deny_unknown_fields` makes verification fail closed: every key dstack can emit into
/// `app-compose.json` must be modeled here, so a field added by a future dstack version is rejected
/// until it is reviewed and modeled, rather than silently ignored. Fields are mirrored from
/// dstack's `AppCompose` (`dstack-types/src/lib.rs`) plus the script keys read directly via `jq`
/// during boot (`pre_launch_script`, `init_script`, `bash_script`). Fields without a security
/// implication are modeled only to absorb their key; they are not validated.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppCompose {
    pub manifest_version: u32,
    pub name: String,
    pub runner: String,
    pub docker_compose_file: DockerComposeString,
    #[serde(default)]
    pub kms_enabled: bool,
    #[serde(default)]
    pub tproxy_enabled: Option<bool>,
    #[serde(default)]
    pub gateway_enabled: Option<bool>,
    #[serde(default)]
    pub public_logs: bool,
    #[serde(default)]
    pub public_sysinfo: bool,
    #[serde(default)]
    pub local_key_provider_enabled: bool,
    #[serde(default)]
    pub key_provider_id: Option<String>,
    #[serde(default)]
    pub allowed_envs: Vec<String>,
    #[serde(default)]
    pub no_instance_id: bool,
    #[serde(default)]
    pub secure_time: Option<bool>,
    #[serde(default)]
    pub pre_launch_script: Option<String>,
    #[serde(default)]
    pub init_script: Option<String>,
    #[serde(default)]
    pub bash_script: Option<String>,
    // Modeled to absorb the key under `deny_unknown_fields`; not validated.
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub public_tcbinfo: Option<bool>,
    #[serde(default)]
    pub key_provider: Option<Value>,
    #[serde(default)]
    pub storage_fs: Option<String>,
    #[serde(default)]
    pub swap_size: Option<Value>,
    // Added in dstack 0.5.11 (0.5.8 never emits it); pre-modeled for future 0.5.11 support. Gateway
    // port config, inert while the gateway is disabled, so no security implication.
    #[serde(default)]
    pub port_policy: Option<Value>,
    #[serde(default)]
    pub docker_config: Option<Value>,
}

/// A type that contains a docker compose the contents of a docker compose file as
/// a string. For example the docker compose file below can be read as a string and initialize this type.
///
/// This type does currently not do any validation of the string
#[derive(Debug, Deserialize, Serialize, BorshSerialize, BorshDeserialize, From, Deref)]
pub struct DockerComposeString(String);
