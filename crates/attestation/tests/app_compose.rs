use attestation::app_compose::AppCompose;
use test_utils::attestation::mock_dstack_attestation;

#[test]
fn test_app_compose_deserialization() {
    let attestation = mock_dstack_attestation();
    let app_compose: AppCompose = serde_json::from_str(&attestation.tcb_info.app_compose).unwrap();

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
