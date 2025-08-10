use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;

/// Custom deserializer to parse YAML string into YamlValue
fn deserialize_yaml_from_string<'de, D>(deserializer: D) -> Result<YamlValue, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let yaml_string = String::deserialize(deserializer)?;
    serde_yaml::from_str(&yaml_string).map_err(serde::de::Error::custom)
}

/// Helper struct to deserialize the `app_compose` JSON from TCB info. This is a workaround due to
/// current limitations in the dstack SDK.
///
/// See: https://github.com/Dstack-TEE/dstack/issues/267
#[derive(Debug, Deserialize, Serialize)]
pub struct AppCompose {
    pub manifest_version: u32,
    pub name: String,
    pub runner: String,
    #[serde(deserialize_with = "deserialize_yaml_from_string")]
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
            "kms_enabled": false,
            "tproxy_enabled": false,
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
        let services = app_compose.docker_compose_file["services"]
            .as_mapping()
            .unwrap();
        let jupyter = &services["jupyter"];

        assert_eq!(
            jupyter["image"].as_str().unwrap(),
            "quay.io/jupyter/base-notebook"
        );
        assert_eq!(jupyter["user"].as_str().unwrap(), "root");

        let environment = jupyter["environment"].as_sequence().unwrap();
        assert_eq!(environment[0].as_str().unwrap(), "GRANT_SUDO=yes");

        let ports = jupyter["ports"].as_sequence().unwrap();
        assert_eq!(ports[0].as_str().unwrap(), "8888:8888");

        let volumes = jupyter["volumes"].as_sequence().unwrap();
        assert_eq!(volumes[0].as_str().unwrap(), "/:/host/");
        assert_eq!(
            volumes[1].as_str().unwrap(),
            "/var/run/tappd.sock:/var/run/tappd.sock"
        );
        assert_eq!(
            volumes[2].as_str().unwrap(),
            "/var/run/dstack.sock:/var/run/dstack.sock"
        );

        let logging = &jupyter["logging"];
        assert_eq!(logging["driver"].as_str().unwrap(), "journald");
        assert_eq!(
            logging["options"]["tag"].as_str().unwrap(),
            "jupyter-notebook"
        );
        assert!(!app_compose.kms_enabled);
        assert_eq!(app_compose.tproxy_enabled, Some(false));
        assert!(app_compose.public_logs);
        assert!(app_compose.public_sysinfo);
        assert!(!app_compose.local_key_provider_enabled);
        assert_eq!(app_compose.allowed_envs, Vec::<String>::new());
        assert!(!app_compose.no_instance_id);

        // Test optional fields
        assert_eq!(app_compose.gateway_enabled, None);
        assert_eq!(app_compose.key_provider_id, None);
        assert_eq!(app_compose.secure_time, None);
        assert_eq!(app_compose.pre_launch_script, None);
    }
}
