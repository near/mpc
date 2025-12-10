use assert_matches::assert_matches;
use attestation::attestation::VerificationError;
use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};
use test_utils::attestation::{
    account_key, image_digest, launcher_compose_digest, mock_dstack_attestation, p2p_tls_key,
};

use mpc_attestation::attestation::{Attestation, MockAttestation};
use mpc_attestation::report_data::{ReportData, ReportDataV1};

#[test]
fn valid_mock_attestation_succeeds_verification() {
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);

    let timestamp_s = 0u64;
    let tls_key = p2p_tls_key();
    let account_key = account_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));

    assert_matches!(
        valid_attestation.verify(report_data.into(), timestamp_s, &[], &[]),
        Ok(_)
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
fn test_verify_method_signature() {
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    let account_key = account_key();

    let report_data = ReportData::V1(ReportDataV1::new(tls_key, account_key));
    let timestamp_s = 1763626832_u64; //Thursday, 20 November 2025 08:20:32

    let allowed_mpc_image_digest: MpcDockerImageHash = image_digest();
    let allowed_launcher_compose_digest: LauncherDockerComposeHash = launcher_compose_digest();

    let verification_result = attestation.verify(
        report_data.into(),
        timestamp_s,
        &[allowed_mpc_image_digest],
        &[allowed_launcher_compose_digest],
    );
    assert!(verification_result.is_ok());
}
