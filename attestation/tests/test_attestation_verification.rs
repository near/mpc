use attestation::report_data::{ReportData, ReportDataV1};
use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};
use near_sdk::PublicKey;
use rstest::rstest;
use test_utils::attestation::{
    TEST_LAUNCHER_COMPOSE_DIGEST_HEX, TEST_MPC_IMAGE_DIGEST_HEX, mock_dstack_attestation,
    mock_local_attestation, p2p_tls_key,
};

#[rstest]
#[case(false, false)]
#[case(true, true)]
fn test_mock_attestation_verify(
    #[case] quote_verification_result: bool,
    #[case] expected_quote_verification_result: bool,
) {
    let timestamp_s = 0u64;
    let tls_key = "ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847"
        .parse()
        .unwrap();
    let report_data = ReportData::V1(ReportDataV1::new(tls_key));

    assert_eq!(
        mock_local_attestation(quote_verification_result).verify(
            report_data,
            timestamp_s,
            &[],
            &[],
        ),
        expected_quote_verification_result
    );
}

#[test]
fn test_verify_method_signature() {
    let attestation = mock_dstack_attestation();
    let tls_key: PublicKey = p2p_tls_key();

    let report_data = ReportData::V1(ReportDataV1::new(tls_key));
    let timestamp_s = 1755186041_u64;

    let allowed_mpc_image_digest =
        MpcDockerImageHash::try_from_hex(TEST_MPC_IMAGE_DIGEST_HEX).unwrap();

    let allowed_launcher_compose_digest =
        LauncherDockerComposeHash::try_from_hex(TEST_LAUNCHER_COMPOSE_DIGEST_HEX).unwrap();

    let verification_result = attestation.verify(
        report_data,
        timestamp_s,
        &[allowed_mpc_image_digest],
        &[allowed_launcher_compose_digest],
    );
    assert!(verification_result);
}
