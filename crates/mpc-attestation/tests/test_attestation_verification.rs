use assert_matches::assert_matches;
use attestation::attestation::VerificationError;
use mpc_attestation::attestation::{
    Attestation, DEFAULT_EXPIRATION_DURATION_SECONDS, MockAttestation, VerifiedAttestation,
};
use mpc_attestation::report_data::{ReportData, ReportDataV1};
use test_utils::attestation::{
    account_key, image_digest, launcher_compose_digest, mock_dstack_attestation, p2p_tls_key,
};

// Unix time as of 2025/01/27 12:25 CET
const MEASUREMENT_TIMESTAMP: u64 = 1769513040;

#[test]
fn valid_mock_attestation_succeeds_verification() {
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);

    let timestamp_s = 0u64;
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));

    assert_matches!(
        valid_attestation.verify(report_data.into(), timestamp_s, &[], &[]),
        Ok(VerifiedAttestation::Mock(MockAttestation::Valid))
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
        valid_attestation.verify(report_data.into(), timestamp_s, &[], &[]),
        Err(VerificationError::InvalidMockAttestation)
    );
}

#[test]
fn validated_dstack_attestation_can_be_reverified() {
    // given
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));
    let timestamp_s = MEASUREMENT_TIMESTAMP;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    let validated = attestation
        .verify(
            report_data.into(),
            timestamp_s,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
        )
        .expect("Initial verification failed");

    // when
    let re_verification_result = validated.re_verify(
        timestamp_s + DEFAULT_EXPIRATION_DURATION_SECONDS,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
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
    let timestamp_s = MEASUREMENT_TIMESTAMP;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    let validated = attestation
        .verify(
            report_data.into(),
            timestamp_s,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
        )
        .expect("Initial verification failed");

    // when
    let re_verification_result = validated.re_verify(
        timestamp_s + DEFAULT_EXPIRATION_DURATION_SECONDS + 1,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
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
        .verify(report_data.into(), 0, &[], &[])
        .expect("Initial verification failed");

    // Mock should generally pass re-verify
    assert_matches!(validated.re_verify(100, &[], &[]), Ok(()));
}

#[test]
fn validated_dstack_attestation_fails_reverification_with_rotated_hashes() {
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = MEASUREMENT_TIMESTAMP;

    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    // 1. Initial verify succeeds with the "old" allowed list
    let validated = attestation
        .verify(
            report_data.into(),
            creation_time,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
        )
        .expect("Initial verification should succeed");

    let new_allowed_mpc_docker_image_hashes = [[42; 32].into()];

    // 2. Re-verify fails if we remove the allowed hash (e.g. strict rotation)
    let result = validated.re_verify(
        creation_time,
        &new_allowed_mpc_docker_image_hashes,
        &allowed_launcher_hashes,
    );

    assert_matches!(
        result,
        Err(VerificationError::Custom(msg))
            if msg.contains("not in the allowed hashes list")
    );
}
