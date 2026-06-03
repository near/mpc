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
    pub tproxy_enabled: Option<bool>,
    pub gateway_enabled: Option<bool>,
    // public_logs / public_sysinfo / local_key_provider_enabled / no_instance_id must be `true`, so
    // they carry no `serde(default)` — a missing one fails to parse. No security gap either way: a
    // defaulted `false` is rejected by `validate_app_compose_config`; dropping it is just clearer.
    // (kms_enabled / allowed_envs keep a default because their default *is* the safe value.)
    pub public_logs: bool,
    pub public_sysinfo: bool,
    pub local_key_provider_enabled: bool,
    pub key_provider_id: Option<String>,
    #[serde(default)]
    pub allowed_envs: Vec<String>,
    pub no_instance_id: bool,
    pub secure_time: Option<bool>,
    pub pre_launch_script: Option<String>,
    pub init_script: Option<String>,
    pub bash_script: Option<String>,
    // The fields below are absorbed only to satisfy `deny_unknown_fields`; they are never read. The
    // structured ones use `IgnoredAny` to avoid allocating attacker-controlled JSON from the
    // untrusted app-compose. (`serde(default)` is omitted on every `Option<_>` field above and
    // below — serde already treats those as optional.)
    pub features: Option<IgnoredAny>,
    pub public_tcbinfo: Option<bool>,
    // Key-provider integrity is pinned by the measured `key-provider` event digest
    // (`verify_key_provider_digest`), not this field.
    pub key_provider: Option<IgnoredAny>,
    pub storage_fs: Option<IgnoredAny>,
    pub swap_size: Option<IgnoredAny>,
    // dstack 0.5.11 gateway field (0.5.8 never emits it); inert while the gateway is disabled.
    pub port_policy: Option<IgnoredAny>,
    pub docker_config: Option<IgnoredAny>,
}

/// A type that contains a docker compose the contents of a docker compose file as
/// a string. For example the docker compose file below can be read as a string and initialize this type.
///
/// This type does currently not do any validation of the string
#[derive(Debug, Deserialize, Serialize, BorshSerialize, BorshDeserialize, From, Deref)]
pub struct DockerComposeString(String);
