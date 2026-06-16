//! Exercises the full local DCAP + post-DCAP path (`verify_locally`), so it
//! requires the off-chain `local-verify` feature.
#![cfg(feature = "local-verify")]

use assert_matches::assert_matches;
use attestation::attestation::VerificationError;
use attestation::measurements::{ExpectedMeasurements, Measurements};
use mpc_attestation::attestation::{
    AcceptedAttestation, Attestation, DEFAULT_EXPIRATION_DURATION_SECONDS, MockAttestation,
    VerifiedAttestation, default_measurements,
};
use mpc_attestation::report_data::{ReportData, ReportDataV1};
use test_utils::attestation::{
    VALID_ATTESTATION_TIMESTAMP, account_key, image_digest, launcher_compose_digest,
    mock_dstack_attestation, p2p_tls_key,
};

#[test]
fn valid_mock_attestation_succeeds_verification() {
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);

    let timestamp_s = 0u64;
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));

    assert_matches!(
        valid_attestation.verify_locally(report_data.into(), timestamp_s, &[], &[], &[]),
        Ok(AcceptedAttestation {
            attestation: VerifiedAttestation::Mock(MockAttestation::Valid),
            advisory_ids,
        }) if advisory_ids.is_empty()
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

/// `verify_locally` (DCAP + post-DCAP) and `verify_with_report` (post-DCAP
/// against a supplied report) must agree: the contract feeds the verifier's
/// report into `verify_with_report`, so it must yield exactly what a full local
/// verify would. This runs DCAP once to obtain the report, then compares.
#[test]
#[expect(non_snake_case)]
fn verify_with_report__should_agree_with_verify_locally() {
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let timestamp_s = VALID_ATTESTATION_TIMESTAMP;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    // Full local verify (DCAP + post-DCAP).
    let local = attestation
        .verify_locally(
            report_data.clone().into(),
            timestamp_s,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            default_measurements(),
        )
        .expect("local verify should succeed");

    // Obtain the report the verifier contract would return (DCAP only), then
    // feed it to the pure post-DCAP path the contract uses.
    let Attestation::Dstack(dstack) = &attestation else {
        panic!("fixture is a Dstack attestation");
    };
    let report = dstack
        .dcap_report(timestamp_s)
        .expect("dcap report should be produced");

    let with_report = attestation
        .verify_with_report(
            &report,
            report_data.into(),
            timestamp_s,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            default_measurements(),
        )
        .expect("verify_with_report should succeed");

    // `VerifiedAttestation` has no `PartialEq`; compare via its Borsh encoding,
    // which is the form actually stored on-chain.
    assert_eq!(
        borsh::to_vec(&local.attestation).unwrap(),
        borsh::to_vec(&with_report.attestation).unwrap(),
    );
    assert_eq!(local.advisory_ids, with_report.advisory_ids);
}

#[test]
fn validated_dstack_attestation_can_be_reverified() {
    // given
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));
    let timestamp_s = VALID_ATTESTATION_TIMESTAMP;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    let validated = attestation
        .verify_locally(
            report_data.into(),
            timestamp_s,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            default_measurements(),
        )
        .expect("Initial verification failed")
        .attestation;

    // when
    let re_verification_result = validated.re_verify(
        timestamp_s + DEFAULT_EXPIRATION_DURATION_SECONDS,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        default_measurements(),
    );

    // then
    assert_matches!(re_verification_result, Ok(()));
}

#[test]
fn validated_dstack_attestation_fails_reverification_when_expired() {
    // given
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));
    let timestamp_s = VALID_ATTESTATION_TIMESTAMP;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    let validated = attestation
        .verify_locally(
            report_data.into(),
            timestamp_s,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            default_measurements(),
        )
        .expect("Initial verification failed")
        .attestation;

    // when
    let re_verification_result = validated.re_verify(
        timestamp_s + DEFAULT_EXPIRATION_DURATION_SECONDS + 1,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        default_measurements(),
    );

    // then
    assert_matches!(
        re_verification_result,
        Err(VerificationError::Custom(msg)) if msg.contains("The attestation expired")
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

#[test]
fn validated_dstack_attestation_fails_reverification_with_rotated_hashes() {
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = VALID_ATTESTATION_TIMESTAMP;

    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    // 1. Initial verify succeeds with the "old" allowed list
    let validated = attestation
        .verify_locally(
            report_data.into(),
            creation_time,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            default_measurements(),
        )
        .expect("Initial verification should succeed")
        .attestation;

    let new_allowed_mpc_docker_image_hashes = [[42; 32].into()];

    // 2. Re-verify fails if we remove the allowed hash (e.g. strict rotation)
    let result = validated.re_verify(
        creation_time,
        &new_allowed_mpc_docker_image_hashes,
        &allowed_launcher_hashes,
        default_measurements(),
    );

    assert_matches!(
        result,
        Err(VerificationError::Custom(msg))
            if msg.contains("not in the allowed hashes list")
    );
}

#[test]
fn validated_dstack_attestation_fails_reverification_with_removed_measurements() {
    // given
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = VALID_ATTESTATION_TIMESTAMP;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    let validated = attestation
        .verify_locally(
            report_data.into(),
            creation_time,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            default_measurements(),
        )
        .expect("Initial verification should succeed")
        .attestation;

    let different_measurements = [ExpectedMeasurements {
        rtmrs: Measurements {
            mrtd: [0xAA; 48],
            rtmr0: [0xBB; 48],
            rtmr1: [0xCC; 48],
            rtmr2: [0xDD; 48],
        },
        key_provider_event_digest: [0xEE; 48],
    }];

    // when
    let result = validated.re_verify(
        creation_time,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        &different_measurements,
    );

    // then
    assert_matches!(result, Err(VerificationError::MeasurementsNotAllowed));
}

#[test]
fn validated_dstack_attestation_fails_reverification_with_empty_measurements() {
    // given
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = VALID_ATTESTATION_TIMESTAMP;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    let validated = attestation
        .verify_locally(
            report_data.into(),
            creation_time,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            default_measurements(),
        )
        .expect("Initial verification should succeed")
        .attestation;

    // when
    let result = validated.re_verify(
        creation_time,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        &[],
    );

    // then
    assert_matches!(result, Err(VerificationError::EmptyMeasurementsList));
}

#[test]
fn validated_dstack_attestation_passes_reverification_with_superset_measurements() {
    // given
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = VALID_ATTESTATION_TIMESTAMP;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    let validated = attestation
        .verify_locally(
            report_data.into(),
            creation_time,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            default_measurements(),
        )
        .expect("Initial verification should succeed")
        .attestation;

    let extra_measurement = ExpectedMeasurements {
        rtmrs: Measurements {
            mrtd: [0xAA; 48],
            rtmr0: [0xBB; 48],
            rtmr1: [0xCC; 48],
            rtmr2: [0xDD; 48],
        },
        key_provider_event_digest: [0xEE; 48],
    };
    let mut superset: Vec<ExpectedMeasurements> = default_measurements().to_vec();
    superset.push(extra_measurement);

    // when
    let result = validated.re_verify(
        creation_time,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        &superset,
    );

    // then
    assert_matches!(result, Ok(()));
}
