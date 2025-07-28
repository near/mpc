use alloc::{format, string::String, vec::Vec};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;

/// Custom deserializer to parse YAML string into YamlValue
fn deserialize_yaml_from_string<'de, D>(deserializer: D) -> Result<YamlValue, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let yaml_string = String::deserialize(deserializer)?;
    serde_yaml::from_str(&yaml_string)
        .map_err(|e| serde::de::Error::custom(format!("Failed to parse YAML: {}", e)))
}

/// Helper struct to deserialize the app_compose JSON from TCB info. This file would never exist if
/// the dstack SDK was designed more cleanly.
///
/// TODO: Open GitHub issue to dstack SDK to use strong types instead of plain String for JSONs and
/// YAMLs.
#[derive(Debug, Deserialize, Serialize)]
pub struct AppCompose {
    pub manifest_version: u32,
    pub name: String,
    pub runner: String,
    #[serde(deserialize_with = "deserialize_yaml_from_string")]
    pub docker_compose_file: YamlValue,
    pub docker_config: JsonValue,
    pub kms_enabled: bool,
    #[serde(default)]
    pub tproxy_enabled: Option<bool>,
    #[serde(default)]
    pub gateway_enabled: Option<bool>,
    pub public_logs: bool,
    pub public_sysinfo: bool,
    pub public_tcbinfo: bool,
    pub local_key_provider_enabled: bool,
    #[serde(default)]
    pub key_provider_id: Option<String>,
    pub allowed_envs: Vec<String>,
    pub no_instance_id: bool,
    #[serde(default)]
    pub secure_time: Option<bool>,
    #[serde(default)]
    pub pre_launch_script: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_compose_deserialization() {
        let app_compose_json = r#"{
            "manifest_version": 2,
            "name": "kvin-nb",
            "runner": "docker-compose",
            "docker_compose_file": "services:\n  jupyter:\n    image: quay.io/jupyter/base-notebook\n    user: root\n    environment:\n      - GRANT_SUDO=yes\n    ports:\n      - \"8888:8888\"\n    volumes:\n      - /:/host/\n      - /var/run/tappd.sock:/var/run/tappd.sock\n      - /var/run/dstack.sock:/var/run/dstack.sock\n    logging:\n      driver: journald\n      options:\n        tag: jupyter-notebook\n",
            "docker_config": {},
            "kms_enabled": true,
            "tproxy_enabled": true,
            "public_logs": true,
            "public_sysinfo": true,
            "public_tcbinfo": false,
            "local_key_provider_enabled": false,
            "allowed_envs": [],
            "no_instance_id": false
        }"#;

        let app_compose: AppCompose = serde_json::from_str(app_compose_json).unwrap();

        assert_eq!(app_compose.manifest_version, 2);
        assert_eq!(app_compose.name, "kvin-nb");
        assert_eq!(app_compose.runner, "docker-compose");

        // Test that docker_compose_file was parsed as YAML
        assert!(app_compose.docker_compose_file.get("services").is_some());
        let services = app_compose.docker_compose_file.get("services").unwrap();
        assert!(services.get("jupyter").is_some());

        // Test that docker_config was parsed as JSON
        assert!(app_compose.docker_config.is_object());
        assert!(app_compose.docker_config.as_object().unwrap().is_empty());

        assert!(app_compose.kms_enabled);
        assert_eq!(app_compose.tproxy_enabled, Some(true));
        assert!(app_compose.public_logs);
        assert!(app_compose.public_sysinfo);
        assert!(!app_compose.public_tcbinfo);
        assert!(!app_compose.local_key_provider_enabled);
        assert_eq!(app_compose.allowed_envs, Vec::<String>::new());
        assert!(app_compose.no_instance_id);

        // Test optional fields
        assert_eq!(app_compose.gateway_enabled, None);
        assert_eq!(app_compose.key_provider_id, None);
        assert_eq!(app_compose.secure_time, None);
        assert_eq!(app_compose.pre_launch_script, None);
    }
}
