use attestation::app_compose::AppCompose;
use dstack_sdk_types::dstack::TcbInfo as DstackTcbInfo;
use serde_json::Value;

use crate::common::{
    TEST_APP_COMPOSE_STRING, TEST_APP_COMPOSE_WITH_SERVICES_STRING,
    TEST_LAUNCHER_IMAGE_COMPOSE_NORMALIZED_STRING, TEST_LAUNCHER_IMAGE_COMPOSE_STRING,
    TEST_TCB_INFO_STRING,
};

pub mod common;

#[test]
fn test_app_compose_deserialization() {
    let app_compose: AppCompose =
        serde_json::from_str(TEST_APP_COMPOSE_WITH_SERVICES_STRING).unwrap();

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

#[test]
fn test_app_compose_from_tcb_info() {
    let dstack_tcb_info: DstackTcbInfo = serde_json::from_str(TEST_TCB_INFO_STRING).unwrap();
    let app_compose = dstack_tcb_info.app_compose;
    assert_eq!(app_compose, TEST_APP_COMPOSE_STRING);
}

#[test]
fn test_launcher_compose_normalized_from_app_compose() {
    let app_compose: AppCompose = serde_json::from_str(TEST_APP_COMPOSE_STRING).unwrap();
    let launcher_compose = serde_yaml::to_string(&app_compose.docker_compose_file).unwrap();
    assert_eq!(
        launcher_compose,
        TEST_LAUNCHER_IMAGE_COMPOSE_NORMALIZED_STRING
    );
}

#[test]
fn test_launcher_compose_from_app_compose() {
    let app_compose: Value = serde_json::from_str(TEST_APP_COMPOSE_STRING).unwrap();
    let launcher_compose = app_compose
        .get("docker_compose_file")
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(launcher_compose, TEST_LAUNCHER_IMAGE_COMPOSE_STRING);
}
