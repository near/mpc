use assert_matches::assert_matches;
use attestation::attestation::VerificationError;
use mpc_attestation::attestation::{Attestation, MockAttestation, VerifiedAttestation};
use mpc_attestation::report_data::{ReportData, ReportDataV1};
use test_utils::attestation::{
    account_key, image_digest, launcher_compose_digest, mock_dstack_attestation, p2p_tls_key,
};

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
    // Setup initial valid verification
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let timestamp_s = 1763626832_u64;
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

    // Test re-verify logic (e.g., checking expiration)
    let max_age = 3600; // 1 hour

    // Case 1: Re-verify with valid time
    let result_valid = validated.re_verify(
        timestamp_s + 100,
        max_age,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
    );
    assert_matches!(result_valid, Ok(()));

    // Case 2: Re-verify with expired time
    let result_expired = validated.re_verify(
        timestamp_s + max_age + 1,
        max_age,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
    );

    assert_matches!(
        result_expired,
        Err(VerificationError::Custom(msg)) if msg.contains("The attestation expired")
    );
}

#[test]
fn validated_mock_attestation_passes_reverification() {
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));

    let validated = valid_attestation
        .verify(report_data.into(), 0, &[], &[])
        .expect("Initial verification failed");

    // Mock should generally pass re-verify
    assert_matches!(validated.re_verify(100, 3600, &[], &[]), Ok(()));
}

#[test]
fn validated_dstack_attestation_fails_reverification_when_expired() {
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();

    let creation_time = 1763626832_u64;
    let allowed_mpc_hashes = [image_digest()];
    let allowed_launcher_hashes = [launcher_compose_digest()];

    // 1. Establish a valid attestation first
    let validated = attestation
        .verify(
            report_data.into(),
            creation_time,
            &allowed_mpc_hashes,
            &allowed_launcher_hashes,
        )
        .expect("Initial verification should succeed");

    // 2. Calculate a time that is strictly AFTER the expiry
    let max_age = 3600; // 1 hour
    let expiry_time = creation_time + max_age;
    let check_time = expiry_time + 1; // 1 second too late

    // 3. Re-verify
    let result = validated.re_verify(
        check_time,
        max_age,
        &allowed_mpc_hashes,
        &allowed_launcher_hashes,
    );

    // 4. Expect failure
    assert_matches!(
        result,
        Err(VerificationError::Custom(msg))
            if msg.contains("The attestation expired")
    );
}

#[test]
fn validated_dstack_attestation_fails_reverification_with_rotated_hashes() {
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();
    let creation_time = 1763626832_u64;

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
        creation_time + 100,
        3600,
        &new_allowed_mpc_docker_image_hashes,
        &allowed_launcher_hashes,
    );

    assert_matches!(
        result,
        Err(VerificationError::Custom(msg))
            if msg.contains("not in the allowed hashes list")
    );
}
