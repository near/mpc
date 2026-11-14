//! Exercises the full local DCAP + post-DCAP path (`verify_locally`), so it
//! requires the off-chain `local-verify` feature.
#![cfg(feature = "local-verify")]
#![expect(non_snake_case)]

use attestation::attestation::VerificationError;
use attestation::{ExpectedMeasurements, Measurements};
use mpc_attestation::attestation::{
    AcceptedAttestation, Attestation, MOCK_EXPIRATION_DURATION_SECONDS, MockAttestation,
    VerifiedAttestation, dev_measurements,
};
use mpc_attestation::report_data::{ReportData, ReportDataV1};
use mpc_primitives::hash::NodeImageHash;
use rstest::rstest;
use std::assert_matches;
use test_utils::attestation::{
    VALID_ATTESTATION_TIMESTAMP, account_key, collateral_dates, image_digest,
    launcher_compose_digest, mock_dstack_attestation, p2p_tls_key,
};

#[test]
fn valid_mock_attestation_succeeds_verification() {
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);

    let timestamp_s = 0u64;
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));

    // A `Valid` mock is accepted as an expiring `WithConstraints` mock so the
    // stored attestation can later be cleaned up (#3293).
    assert_matches!(
        valid_attestation.verify_locally(report_data.into(), timestamp_s, &[], &[], &[]),
        Ok(AcceptedAttestation {
            attestation: VerifiedAttestation::Mock(MockAttestation::WithConstraints {
                mpc_docker_image_hash: None,
                launcher_docker_compose_hash: None,
                expiry_timestamp_seconds: Some(expiry),
                expected_measurements: None,
            }),
            advisory_ids,
        }) if advisory_ids.is_empty() && expiry == timestamp_s + MOCK_EXPIRATION_DURATION_SECONDS
    );
}

#[test]
fn invalid_mock_attestation_fails_verification() {
    let valid_attestation = Attestation::Mock(MockAttestation::Invalid);

    let timestamp_s = 0u64;
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));

    assert_matches!(
        valid_attestation.verify_locally(report_data.into(), timestamp_s, &[], &[], &[]),
        Err(VerificationError::InvalidMockAttestation)
    );
}

#[test]
fn validated_mock_attestation_passes_reverification() {
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();

    let validated = valid_attestation
        .verify_locally(report_data.into(), 0, &[], &[], &[])
        .expect("Initial verification failed")
        .attestation;

    // Mock should generally pass re-verify
    assert_matches!(validated.re_verify(100, &[], &[], &[]), Ok(()));
}

fn validated_dstack_attestation() -> VerifiedAttestation {
    let report_data: ReportData = ReportDataV1::new(p2p_tls_key(), account_key()).into();

    mock_dstack_attestation()
        .verify_locally(
            report_data.into(),
            VALID_ATTESTATION_TIMESTAMP,
            &[image_digest()],
            &[launcher_compose_digest()],
            &[dev_measurements()],
        )
        .expect("Initial verification should succeed")
        .attestation
}

fn other_measurements() -> ExpectedMeasurements {
    ExpectedMeasurements {
        rtmrs: Measurements {
            mrtd: [0xAA; 48],
            rtmr0: [0xBB; 48],
            rtmr1: [0xCC; 48],
            rtmr2: [0xDD; 48],
        },
        key_provider_event_digest: [0xEE; 48],
    }
}

#[rstest]
#[case::dev_measurements_at_expiration_date(
    collateral_dates().earliest_expiration_date,
    vec![dev_measurements()],
    Ok(())
)]
#[case::removed_measurements(
    VALID_ATTESTATION_TIMESTAMP,
    vec![other_measurements()],
    Err(VerificationError::MeasurementsNotAllowed)
)]
#[case::empty_measurements(
    VALID_ATTESTATION_TIMESTAMP,
    vec![],
    Err(VerificationError::EmptyMeasurementsList)
)]
#[case::superset_measurements(
    VALID_ATTESTATION_TIMESTAMP,
    vec![dev_measurements(), other_measurements()],
    Ok(())
)]
fn validated_dstack_attestation__should_reverify_only_with_allowed_measurements(
    #[case] reverification_time: u64,
    #[case] allowed_measurements: Vec<ExpectedMeasurements>,
    #[case] expected: Result<(), VerificationError>,
) {
    // Given
    let validated = validated_dstack_attestation();

    // When
    let result = validated.re_verify(
        reverification_time,
        &[image_digest()],
        &[launcher_compose_digest()],
        &allowed_measurements,
    );

    // Then
    assert_eq!(result, expected);
}

#[rstest]
#[case::expired(
    collateral_dates().earliest_expiration_date + 1,
    vec![image_digest()],
    "The attestation expired"
)]
#[case::rotated_hashes(
    VALID_ATTESTATION_TIMESTAMP,
    vec![[42; 32].into()],
    "not in the allowed hashes list"
)]
fn validated_dstack_attestation__should_fail_reverification(
    #[case] reverification_time: u64,
    #[case] allowed_mpc_hashes: Vec<NodeImageHash>,
    #[case] expected_message_fragment: &str,
) {
    // Given
    let validated = validated_dstack_attestation();

    // When
    let result = validated.re_verify(
        reverification_time,
        &allowed_mpc_hashes,
        &[launcher_compose_digest()],
        &[dev_measurements()],
    );

    // Then
    assert_matches!(
        result,
        Err(VerificationError::Custom(msg)) if msg.contains(expected_message_fragment)
    );
}
