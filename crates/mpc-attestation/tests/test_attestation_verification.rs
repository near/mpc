//! Exercises the full local DCAP + post-DCAP path (`verify_locally`), so it
//! requires the off-chain `local-verify` feature.
#![cfg(feature = "local-verify")]

use attestation::attestation::VerificationError;
use attestation::{ExpectedMeasurements, Measurements};
use mpc_attestation::attestation::{
    AcceptedAttestation, Attestation, MOCK_EXPIRATION_DURATION_SECONDS, MockAttestation,
    VerifiedAttestation,
};
use mpc_attestation::report_data::{ReportData, ReportDataV1};
use rstest::rstest;
use std::assert_matches;
use test_utils::attestation::{
    AttestationFixture, DSTACK_0_5_8, DSTACK_0_6_5, account_key, p2p_tls_key,
};

#[test]
fn valid_mock_attestation_succeeds_verification() {
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);

    let timestamp_s = 0u64;
    let tls_key = p2p_tls_key().0;
    let account_key = account_key().0;
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
    let tls_key = p2p_tls_key().0;
    let account_key = account_key().0;
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));

    assert_matches!(
        valid_attestation.verify_locally(report_data.into(), timestamp_s, &[], &[], &[]),
        Err(VerificationError::InvalidMockAttestation)
    );
}

#[rstest]
fn validated_dstack_attestation_can_be_reverified(
    #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
) {
    // given
    let attestation = fixture.dstack_attestation();
    let tls_key = fixture.p2p_tls_key().0;
    let account_key = fixture.account_key().0;
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));
    let timestamp_s = fixture.valid_timestamp;
    let allowed_mpc_hashes = [fixture.image_digest()];
    let allowed_launcher_hashes = [fixture.launcher_compose_digest()];

    let validated = attestation
        .verify_locally(
            report_data.into(),
            timestamp_s,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            &[fixture.measurements],
        )
        .expect("Initial verification failed")
        .attestation;

    // when
    let re_verification_result = validated.re_verify(
        fixture.collateral_dates().earliest_expiration_date,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        &[fixture.measurements],
    );

    // then
    assert_matches!(re_verification_result, Ok(()));
}

#[rstest]
fn validated_dstack_attestation_fails_reverification_when_expired(
    #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
) {
    // given
    let attestation = fixture.dstack_attestation();
    let tls_key = fixture.p2p_tls_key().0;
    let account_key = fixture.account_key().0;
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));
    let timestamp_s = fixture.valid_timestamp;
    let allowed_mpc_hashes = [fixture.image_digest()];
    let allowed_launcher_hashes = [fixture.launcher_compose_digest()];

    let validated = attestation
        .verify_locally(
            report_data.into(),
            timestamp_s,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            &[fixture.measurements],
        )
        .expect("Initial verification failed")
        .attestation;

    // when
    let re_verification_result = validated.re_verify(
        fixture.collateral_dates().earliest_expiration_date + 1,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
        &[fixture.measurements],
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
    let tls_key = p2p_tls_key().0;
    let account_key = account_key().0;
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();

    let validated = valid_attestation
        .verify_locally(report_data.into(), 0, &[], &[], &[])
        .expect("Initial verification failed")
        .attestation;

    // Mock should generally pass re-verify
    assert_matches!(validated.re_verify(100, &[], &[], &[]), Ok(()));
}

#[rstest]
fn validated_dstack_attestation_fails_reverification_with_rotated_hashes(
    #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
) {
    let attestation = fixture.dstack_attestation();
    let tls_key = fixture.p2p_tls_key().0;
    let account_key = fixture.account_key().0;
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = fixture.valid_timestamp;

    let allowed_mpc_hashes = [fixture.image_digest()];
    let allowed_launcher_hashes = [fixture.launcher_compose_digest()];

    // 1. Initial verify succeeds with the "old" allowed list
    let validated = attestation
        .verify_locally(
            report_data.into(),
            creation_time,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            &[fixture.measurements],
        )
        .expect("Initial verification should succeed")
        .attestation;

    let new_allowed_mpc_docker_image_hashes = [[42; 32].into()];

    // 2. Re-verify fails if we remove the allowed hash (e.g. strict rotation)
    let result = validated.re_verify(
        creation_time,
        &new_allowed_mpc_docker_image_hashes,
        &allowed_launcher_hashes,
        &[fixture.measurements],
    );

    assert_matches!(
        result,
        Err(VerificationError::Custom(msg))
            if msg.contains("not in the allowed hashes list")
    );
}

#[rstest]
fn validated_dstack_attestation_fails_reverification_with_removed_measurements(
    #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
) {
    // given
    let attestation = fixture.dstack_attestation();
    let tls_key = fixture.p2p_tls_key().0;
    let account_key = fixture.account_key().0;
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = fixture.valid_timestamp;
    let allowed_mpc_hashes = [fixture.image_digest()];
    let allowed_launcher_hashes = [fixture.launcher_compose_digest()];

    let validated = attestation
        .verify_locally(
            report_data.into(),
            creation_time,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            &[fixture.measurements],
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

#[rstest]
fn validated_dstack_attestation_fails_reverification_with_empty_measurements(
    #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
) {
    // given
    let attestation = fixture.dstack_attestation();
    let tls_key = fixture.p2p_tls_key().0;
    let account_key = fixture.account_key().0;
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = fixture.valid_timestamp;
    let allowed_mpc_hashes = [fixture.image_digest()];
    let allowed_launcher_hashes = [fixture.launcher_compose_digest()];

    let validated = attestation
        .verify_locally(
            report_data.into(),
            creation_time,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            &[fixture.measurements],
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

#[rstest]
fn validated_dstack_attestation_passes_reverification_with_superset_measurements(
    #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
) {
    // given
    let attestation = fixture.dstack_attestation();
    let tls_key = fixture.p2p_tls_key().0;
    let account_key = fixture.account_key().0;
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = fixture.valid_timestamp;
    let allowed_mpc_hashes = [fixture.image_digest()];
    let allowed_launcher_hashes = [fixture.launcher_compose_digest()];

    let validated = attestation
        .verify_locally(
            report_data.into(),
            creation_time,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
            &[fixture.measurements],
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
    let mut superset: Vec<ExpectedMeasurements> = vec![fixture.measurements];
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
