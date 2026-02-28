use std::path::PathBuf;

use attestation_cli::cli::VerifyArgs;
use attestation_cli::verify;
use ed25519_dalek::VerifyingKey;
use mpc_attestation::attestation::Attestation;
use node_types::http_server::StaticWebData;
use test_utils::attestation::{
    TEST_LAUNCHER_IMAGE_COMPOSE_STRING, TEST_MPC_IMAGE_DIGEST_HEX, VALID_ATTESTATION_TIMESTAMP,
    account_key, mock_dstack_attestation, p2p_tls_key,
};

fn make_static_web_data(attestation: Attestation) -> StaticWebData {
    let p2p_key = VerifyingKey::from_bytes(&p2p_tls_key()).expect("valid p2p key");
    let account = VerifyingKey::from_bytes(&account_key()).expect("valid account key");

    StaticWebData {
        near_signer_public_key: account,
        near_p2p_public_key: p2p_key,
        near_responder_public_keys: vec![],
        tee_participant_info: Some(attestation),
    }
}

fn make_verify_args(
    compose_path: &std::path::Path,
    image_hash: &str,
    measurements: Option<PathBuf>,
) -> VerifyArgs {
    VerifyArgs {
        url: None,
        file: None,
        allowed_image_hashes: vec![image_hash.to_string()],
        launcher_compose_file: compose_path.to_path_buf(),
        expected_measurements: measurements,
    }
}

#[test]
fn full_verification_succeeds_with_valid_mock_attestation() {
    let attestation = mock_dstack_attestation();

    let Attestation::Dstack(ref dstack) = attestation else {
        panic!("expected Dstack attestation");
    };

    let static_data = make_static_web_data(attestation.clone());

    // Write the launcher compose to a temp file
    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("launcher-compose.yaml");
    std::fs::write(&compose_path, TEST_LAUNCHER_IMAGE_COMPOSE_STRING).unwrap();

    let args = make_verify_args(&compose_path, TEST_MPC_IMAGE_DIGEST_HEX, None);

    let result = verify::verify_dstack_at_timestamp(
        &static_data,
        dstack,
        &args,
        VALID_ATTESTATION_TIMESTAMP,
    );

    assert!(
        result.is_ok(),
        "verification failed: {}",
        result.unwrap_err()
    );
    let result = result.unwrap();
    assert_eq!(result.mpc_image_hash.as_hex(), TEST_MPC_IMAGE_DIGEST_HEX);
    assert_eq!(
        result.expiry_timestamp_seconds,
        VALID_ATTESTATION_TIMESTAMP + 60 * 60 * 24 * 7
    );
}

#[test]
fn verification_fails_with_wrong_image_hash() {
    let attestation = mock_dstack_attestation();
    let Attestation::Dstack(ref dstack) = attestation else {
        panic!("expected Dstack attestation");
    };

    let static_data = make_static_web_data(attestation.clone());

    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("launcher-compose.yaml");
    std::fs::write(&compose_path, TEST_LAUNCHER_IMAGE_COMPOSE_STRING).unwrap();

    let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let args = make_verify_args(&compose_path, wrong_hash, None);

    let result = verify::verify_dstack_at_timestamp(
        &static_data,
        dstack,
        &args,
        VALID_ATTESTATION_TIMESTAMP,
    );

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not in the allowed list"),
        "unexpected error: {err}"
    );
}

#[test]
fn verification_fails_with_wrong_compose_file() {
    let attestation = mock_dstack_attestation();
    let Attestation::Dstack(ref dstack) = attestation else {
        panic!("expected Dstack attestation");
    };

    let static_data = make_static_web_data(attestation.clone());

    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("launcher-compose.yaml");
    std::fs::write(&compose_path, "wrong compose content").unwrap();

    let args = make_verify_args(&compose_path, TEST_MPC_IMAGE_DIGEST_HEX, None);

    let result = verify::verify_dstack_at_timestamp(
        &static_data,
        dstack,
        &args,
        VALID_ATTESTATION_TIMESTAMP,
    );

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not in the allowed list"),
        "unexpected error: {err}"
    );
}

#[test]
fn run_verification_rejects_none_attestation() {
    let static_data = StaticWebData {
        near_signer_public_key: VerifyingKey::from_bytes(&account_key()).unwrap(),
        near_p2p_public_key: VerifyingKey::from_bytes(&p2p_tls_key()).unwrap(),
        near_responder_public_keys: vec![],
        tee_participant_info: None,
    };

    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("launcher-compose.yaml");
    std::fs::write(&compose_path, "content").unwrap();

    let args = make_verify_args(
        &compose_path,
        "0000000000000000000000000000000000000000000000000000000000000000",
        None,
    );

    let result = verify::run_verification(&static_data, &args);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("tee_participant_info is null"),
        "unexpected error: {err}"
    );
}

#[test]
fn run_verification_rejects_mock_attestation() {
    let static_data = StaticWebData {
        near_signer_public_key: VerifyingKey::from_bytes(&account_key()).unwrap(),
        near_p2p_public_key: VerifyingKey::from_bytes(&p2p_tls_key()).unwrap(),
        near_responder_public_keys: vec![],
        tee_participant_info: Some(Attestation::Mock(
            mpc_attestation::attestation::MockAttestation::Valid,
        )),
    };

    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("launcher-compose.yaml");
    std::fs::write(&compose_path, "content").unwrap();

    let args = make_verify_args(
        &compose_path,
        "0000000000000000000000000000000000000000000000000000000000000000",
        None,
    );

    let result = verify::run_verification(&static_data, &args);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Mock"), "unexpected error: {err}");
}

#[test]
fn verification_with_custom_measurements_file() {
    let attestation = mock_dstack_attestation();
    let Attestation::Dstack(ref dstack) = attestation else {
        panic!("expected Dstack attestation");
    };

    let static_data = make_static_web_data(attestation.clone());

    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("launcher-compose.yaml");
    std::fs::write(&compose_path, TEST_LAUNCHER_IMAGE_COMPOSE_STRING).unwrap();

    // Write the test TCB info as a custom measurements file
    let measurements_path = dir.path().join("measurements.json");
    std::fs::write(
        &measurements_path,
        test_utils::attestation::TEST_TCB_INFO_STRING,
    )
    .unwrap();

    let args = make_verify_args(
        &compose_path,
        TEST_MPC_IMAGE_DIGEST_HEX,
        Some(measurements_path),
    );

    let result = verify::verify_dstack_at_timestamp(
        &static_data,
        dstack,
        &args,
        VALID_ATTESTATION_TIMESTAMP,
    );

    assert!(
        result.is_ok(),
        "verification failed: {}",
        result.unwrap_err()
    );
}
