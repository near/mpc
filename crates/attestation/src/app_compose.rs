use alloc::{string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Deref, From};
use serde::{Deserialize, Serialize, de::IgnoredAny};

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
#[derive(Debug, Deserialize)]
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
    // The fields below are absorbed only to satisfy `deny_unknown_fields`; they are never read, so
    // they deserialize as `IgnoredAny` to avoid allocating attacker-controlled JSON from the
    // untrusted app-compose. `key_provider` integrity is pinned by the measured `key-provider`
    // event digest (`verify_key_provider_digest`), not this field. `port_policy` is a dstack 0.5.11
    // gateway field (0.5.8 never emits it), inert while the gateway is disabled.
    #[serde(default)]
    pub features: Option<IgnoredAny>,
    #[serde(default)]
    pub public_tcbinfo: Option<bool>,
    #[serde(default)]
    pub key_provider: Option<IgnoredAny>,
    #[serde(default)]
    pub storage_fs: Option<String>,
    #[serde(default)]
    pub swap_size: Option<IgnoredAny>,
    #[serde(default)]
    pub port_policy: Option<IgnoredAny>,
    #[serde(default)]
    pub docker_config: Option<IgnoredAny>,
}

/// A type that contains a docker compose the contents of a docker compose file as
/// a string. For example the docker compose file below can be read as a string and initialize this type.
///
/// This type does currently not do any validation of the string
#[derive(Debug, Deserialize, Serialize, BorshSerialize, BorshDeserialize, From, Deref)]
pub struct DockerComposeString(String);
