use alloc::{format, string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;

/// Helper struct to deserialize the `app_compose` JSON from TCB info. This is a workaround due to
/// current limitations in the Dstack SDK.
///
/// See: https://github.com/Dstack-TEE/dstack/issues/267
#[derive(Debug, Deserialize, Serialize, BorshSerialize, BorshDeserialize)]
pub struct AppCompose {
    pub manifest_version: u32,
    pub name: String,
    pub runner: String,
    #[borsh(
        deserialize_with = "borsh_deserialize_yaml_from_string",
        serialize_with = "borsh_serialize_yaml_from_string"
    )]
    #[serde(deserialize_with = "serde_deserialize_yaml_from_string")]
    pub docker_compose_file: YamlValue,
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

/// Custom deserializer to parse YAML string into YamlValue
fn serde_deserialize_yaml_from_string<'de, D>(deserializer: D) -> Result<YamlValue, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let yaml_string = <String as Deserialize>::deserialize(deserializer)?;
    serde_yaml::from_str(&yaml_string).map_err(serde::de::Error::custom)
}

fn borsh_deserialize_yaml_from_string<R: borsh::io::Read>(
    reader: &mut R,
) -> ::core::result::Result<YamlValue, borsh::io::Error> {
    let yaml_string = String::deserialize_reader(reader)?;

    serde_yaml::from_str(&yaml_string).map_err(|e| {
        borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            format!("Failed to parse YAML: {}", e),
        )
    })
}

fn borsh_serialize_yaml_from_string<W: borsh::io::Write>(
    yaml_value: &YamlValue,
    writer: &mut W,
) -> ::core::result::Result<(), borsh::io::Error> {
    let yaml_string = serde_yaml::to_string(yaml_value).map_err(|e| {
        borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            format!("Failed to serialize YAML: {}", e),
        )
    })?;

    BorshSerialize::serialize(&yaml_string, writer)
}
