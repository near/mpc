use dstack_sdk_types::dstack::TcbInfo as DstackTcbInfo;
use serde_json::Value;

use attestation::app_compose::AppCompose;
use test_utils::attestation::{
    TEST_APP_COMPOSE_STRING, TEST_APP_COMPOSE_WITH_SERVICES_STRING,
    TEST_LAUNCHER_IMAGE_COMPOSE_STRING, TEST_TCB_INFO_STRING,
};

#[test]
fn test_app_compose_deserialization() {
    let app_compose: AppCompose =
        serde_json::from_str(TEST_APP_COMPOSE_WITH_SERVICES_STRING).unwrap();

    assert_eq!(app_compose.manifest_version, 2);
    assert_eq!(app_compose.name, "kvin-nb");
    assert_eq!(app_compose.runner, "docker-compose");

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
fn test_launcher_compose_from_app_compose() {
    let app_compose: Value = serde_json::from_str(TEST_APP_COMPOSE_STRING).unwrap();
    let launcher_compose = app_compose
        .get("docker_compose_file")
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(launcher_compose, TEST_LAUNCHER_IMAGE_COMPOSE_STRING);
}
