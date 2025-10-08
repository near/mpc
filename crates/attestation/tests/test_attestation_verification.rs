use attestation::{
    attestation::{Attestation, MockAttestation},
    report_data::{ReportData, ReportDataV1},
};
use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};
use rstest::rstest;
use test_utils::attestation::{
    image_digest, launcher_compose_digest, mock_dstack_attestation, p2p_tls_key,
};

#[rstest]
#[case(MockAttestation::Valid, true)]
#[case(MockAttestation::Invalid, false)]
fn test_mock_attestation_verify(
    #[case] local_attestation: MockAttestation,
    #[case] expected_quote_verification_result: bool,
) {
    let timestamp_s = 0u64;
    let tls_key = p2p_tls_key();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key));
    let attestation = Attestation::Mock(local_attestation);

    assert_eq!(
        attestation.verify(report_data, timestamp_s, &[], &[],),
        expected_quote_verification_result
    );
}

#[test]
fn test_verify_method_signature() {
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();

    let report_data = ReportData::V1(ReportDataV1::new(tls_key));
    let timestamp_s = 1755186041_u64;

    let allowed_mpc_image_digest: MpcDockerImageHash = image_digest();
    let allowed_launcher_compose_digest: LauncherDockerComposeHash = launcher_compose_digest();

    let verification_result = attestation.verify(
        report_data,
        timestamp_s,
        &[allowed_mpc_image_digest],
        &[allowed_launcher_compose_digest],
    );
    assert!(verification_result);
}
