use std::assert_matches;
use std::path::PathBuf;

use attestation_cli::cli::{Source, VerifyArgs};
use attestation_cli::verify;
use mpc_attestation::attestation::{Attestation, VerificationError};
use near_mpc_crypto_types::Ed25519PublicKey;
use node_types::http_server::StaticWebData;
use rstest::rstest;
use test_utils::attestation::{
    AttestationFixture, DSTACK_0_5_8, DSTACK_0_6_5, account_key, p2p_tls_key,
};

fn make_static_web_data(fixture: &AttestationFixture) -> StaticWebData {
    StaticWebData {
        near_signer_public_key: Ed25519PublicKey(fixture.account_key()),
        near_p2p_public_key: Ed25519PublicKey(fixture.p2p_tls_key()),
        tee_participant_info: Some(fixture.dstack_attestation()),
    }
}

fn make_args(
    compose_path: &std::path::Path,
    image_hash: &str,
    measurements: Option<PathBuf>,
) -> VerifyArgs {
    VerifyArgs {
        source: Source {
            url: None,
            file: None,
        },
        allowed_image_hashes: vec![image_hash.parse().expect("valid image hash hex")],
        launcher_compose_file: compose_path.to_path_buf(),
        expected_measurements: measurements,
    }
}

#[rstest]
fn full_verification_succeeds_with_valid_attestation(
    #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
) {
    let static_data = make_static_web_data(fixture);

    // Write the launcher compose to a temp file
    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("launcher-compose.yaml");
    std::fs::write(&compose_path, fixture.launcher_compose).unwrap();

    let args = make_args(
        &compose_path,
        fixture.mpc_image_digest_hex,
        Some(fixture.asset_path("tcb_info.json")),
    );

    let result = verify::verify_at_timestamp(&static_data, &args, fixture.valid_timestamp);

    assert!(
        result.is_ok(),
        "verification failed: {}",
        result.unwrap_err()
    );
    let result = result.unwrap();
    assert_eq!(result.mpc_image_hash.as_hex(), fixture.mpc_image_digest_hex);
    assert_eq!(
        result.expiry_timestamp_seconds,
        fixture.collateral_dates().earliest_expiration_date
    );
}

#[rstest]
fn verification_fails_with_wrong_image_hash(
    #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
) {
    let static_data = make_static_web_data(fixture);

    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("launcher-compose.yaml");
    std::fs::write(&compose_path, fixture.launcher_compose).unwrap();

    let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let args = make_args(
        &compose_path,
        wrong_hash,
        Some(fixture.asset_path("tcb_info.json")),
    );

    let result = verify::verify_at_timestamp(&static_data, &args, fixture.valid_timestamp);

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not in the allowed"),
        "unexpected error: {err}"
    );
}

#[rstest]
fn verification_fails_with_wrong_compose_file(
    #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
) {
    let static_data = make_static_web_data(fixture);

    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("launcher-compose.yaml");
    std::fs::write(&compose_path, "wrong compose content").unwrap();

    let args = make_args(
        &compose_path,
        fixture.mpc_image_digest_hex,
        Some(fixture.asset_path("tcb_info.json")),
    );

    let result = verify::verify_at_timestamp(&static_data, &args, fixture.valid_timestamp);

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not in the allowed"),
        "unexpected error: {err}"
    );
}

#[test]
fn run_verification_rejects_none_attestation() {
    let static_data = StaticWebData {
        near_signer_public_key: Ed25519PublicKey(account_key()),
        near_p2p_public_key: Ed25519PublicKey(p2p_tls_key()),
        tee_participant_info: None,
    };

    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("launcher-compose.yaml");
    std::fs::write(&compose_path, "content").unwrap();

    let args = make_args(
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
        near_signer_public_key: Ed25519PublicKey(account_key()),
        near_p2p_public_key: Ed25519PublicKey(p2p_tls_key()),
        tee_participant_info: Some(Attestation::Mock(
            mpc_attestation::attestation::MockAttestation::Valid,
        )),
    };

    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("launcher-compose.yaml");
    std::fs::write(&compose_path, "content").unwrap();

    let args = make_args(
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
#[expect(non_snake_case)]
fn verify_at_timestamp__should_reject_dev_image_attestation_with_default_measurements() {
    // Given
    let fixture = &DSTACK_0_5_8;
    let static_data = make_static_web_data(fixture);
    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("launcher-compose.yaml");
    std::fs::write(&compose_path, fixture.launcher_compose).unwrap();
    let args = make_args(&compose_path, fixture.mpc_image_digest_hex, None);

    // When
    let result = verify::verify_at_timestamp(&static_data, &args, fixture.valid_timestamp);

    // Then
    assert_matches!(
        result,
        Err(VerificationError::WrongHash {
            name: "expected_measurements",
            ..
        })
    );
}

#[test]
#[expect(non_snake_case)]
fn verify_at_timestamp__should_accept_dstack_0_6_5_attestation_with_default_measurements() {
    // Given
    let fixture = &DSTACK_0_6_5;
    let static_data = make_static_web_data(fixture);
    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("launcher-compose.yaml");
    std::fs::write(&compose_path, fixture.launcher_compose).unwrap();
    let args = make_args(&compose_path, fixture.mpc_image_digest_hex, None);

    // When
    let result = verify::verify_at_timestamp(&static_data, &args, fixture.valid_timestamp);

    // Then
    assert_eq!(result.unwrap().measurements, fixture.measurements);
}
