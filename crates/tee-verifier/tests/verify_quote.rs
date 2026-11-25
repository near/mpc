//! Integration tests for the `tee-verifier` contract, calling its methods
//! directly with the `test-utils` fixture.

#![expect(non_snake_case)]

use mpc_attestation::attestation::{
    AcceptedAttestation, Attestation, DstackAttestation, VerifiedAttestation,
};
use mpc_attestation::report_data::{ReportData, ReportDataV1};
use near_sdk::{test_utils::VMContextBuilder, testing_env};
use rstest::rstest;
use std::time::Duration;
use tee_verifier::TeeVerifier;
use tee_verifier_interface::{
    Collateral, CollateralDates, QuoteBytes, Report, TDReport10, TcbStatus, TcbStatusWithAdvisory,
    VerificationResult, VerificationResultWithCollateralDates, VerifiedReport, VerifierError,
};
use test_utils::attestation::{
    AttestationFixture, DSTACK_0_5_8, DSTACK_0_6_5, VALID_ATTESTATION_TIMESTAMP, collateral, quote,
};

fn make_quote_bytes() -> QuoteBytes {
    QuoteBytes(Vec::from(quote()))
}

fn set_timestamp_context(now: Duration) {
    let block_timestamp_ns =
        u64::try_from(now.as_nanos()).expect("timestamp in nanoseconds fits in u64");
    testing_env!(
        VMContextBuilder::new()
            .block_timestamp(block_timestamp_ns)
            .build()
    );
}

/// Sets a VM context whose block timestamp makes the fixture's collateral
/// current, so DCAP verification of the valid fixture succeeds.
fn set_valid_timestamp_context() {
    set_timestamp_context(Duration::from_secs(VALID_ATTESTATION_TIMESTAMP));
}

#[test]
fn verify_quote__should_return_verified_td10_report_for_valid_fixture() {
    // Given
    set_valid_timestamp_context();
    let contract = TeeVerifier::default();
    let quote = make_quote_bytes();
    let collateral = collateral();

    // When
    let result = contract.verify_quote(quote, collateral);

    // Then
    let expected_report = VerifiedReport {
        status: "UpToDate".to_string(),
        advisory_ids: vec![],
        report: Report::TD10(TDReport10 {
            tee_tcb_svn: hex_arr("0b010400000000000000000000000000"),
            mr_seam: hex_arr(
                "7bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d",
            ),
            mr_signer_seam: hex_arr(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
            seam_attributes: hex_arr("0000000000000000"),
            td_attributes: hex_arr("0000001000000000"),
            xfam: hex_arr("e702060000000000"),
            mr_td: hex_arr(
                "2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70",
            ),
            mr_config_id: hex_arr(
                "014d4e66730a5ec377c6a62f6f625357eef218eb13c6d454eb1dbb6126d3f0d11c000000000000000000000000000000",
            ),
            mr_owner: hex_arr(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
            mr_owner_config: hex_arr(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
            rt_mr0: hex_arr(
                "e673be2f70beefb70b48a6109eed4715d7270d4683b3bf356fa25fafbf1aa76e39e9127e6e688ccda98bdab1d4d47f46",
            ),
            rt_mr1: hex_arr(
                "2f72a4db2f7de90adeabe55607b0c1cf209fc243bc773f5862d1b00d3bb198e835e99d502e90a24005f0d1368dd24f29",
            ),
            rt_mr2: hex_arr(
                "3d9910a33a26a769c5146dea31bea0d2924a7746ad09e121dabe709eddd5c647716f4d89279e0e24d8dbb93f9cdb605b",
            ),
            rt_mr3: hex_arr(
                "cf69f48b11123559a95c95995fb69df9a6517da84624939f2cf5083d04edf8e5a7939f230bd63b4f8ac221dc0bddd0cf",
            ),
            report_data: hex_arr(
                "0001fb43a45339ebed05bfa22d423b773a32ed03242d69ee41775183f4848b39effba439103a1215d8c15213def5d029b1c20000000000000000000000000000",
            ),
        }),
        ppid: hex::decode("d208dfb1002346ae1bb4ef2a3c055292").unwrap(),
        qe_status: TcbStatusWithAdvisory {
            status: TcbStatus::UpToDate,
            advisory_ids: vec![],
        },
        platform_status: TcbStatusWithAdvisory {
            status: TcbStatus::UpToDate,
            advisory_ids: vec![],
        },
    };
    assert_eq!(result, VerificationResult::Verified(expected_report));
}

#[rstest]
fn verify_quote__should_verify_the_fixture_at_its_valid_timestamp(
    #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
) {
    // Given
    set_timestamp_context(Duration::from_secs(fixture.valid_timestamp));
    let contract = TeeVerifier::default();

    // When
    let result =
        contract.verify_quote(QuoteBytes(Vec::from(fixture.quote())), fixture.collateral());

    // Then
    assert!(
        matches!(result, VerificationResult::Verified(_)),
        "expected Verified(_), got {result:?}"
    );
}

#[test]
fn verify_quote__should_reject_valid_fixture_when_block_time_is_past_collateral_validity() {
    // Given: block time far past the fixture collateral's validity window
    set_timestamp_context(ten_years_after_fixture());
    let contract = TeeVerifier::default();
    let quote = make_quote_bytes();
    let collateral = collateral();

    // When
    let result = contract.verify_quote(quote, collateral);

    // Then
    assert!(
        matches!(
            result,
            VerificationResult::Rejected(VerifierError::DcapVerification(_))
        ),
        "expected Rejected(DcapVerification(_)), got {result:?}"
    );
}

#[test]
fn verify_quote__should_reject_without_panicking_for_invalid_quote() {
    // Given: a structurally broken quote against otherwise-valid collateral.
    set_valid_timestamp_context();
    let contract = TeeVerifier::default();
    let collateral = collateral();

    // When
    let result = contract.verify_quote(invalid_quote(), collateral);

    // Then: a Rejected value, not a panic, and it carries a reason.
    assert!(
        matches!(
            result,
            VerificationResult::Rejected(VerifierError::DcapVerification(_))
        ),
        "expected Rejected(DcapVerification(_)), got {result:?}"
    );
}

#[test]
fn verify_quote__should_reject_valid_quote_with_mismatched_collateral() {
    // Given
    set_valid_timestamp_context();
    let contract = TeeVerifier::default();
    let quote = make_quote_bytes();

    // When
    let result = contract.verify_quote(quote, mismatched_collateral());

    // Then
    assert!(
        matches!(
            result,
            VerificationResult::Rejected(VerifierError::DcapVerification(_))
        ),
        "expected Rejected(DcapVerification(_)), got {result:?}"
    );
}

#[test]
fn verify_quote_with_collateral_dates__should_return_verify_quote_report_and_fixture_dates() {
    // Given
    set_valid_timestamp_context();
    let contract = TeeVerifier::default();
    let VerificationResult::Verified(expected_report) =
        contract.verify_quote(make_quote_bytes(), collateral())
    else {
        panic!("verify_quote must accept the valid fixture");
    };

    // When
    let result = contract.verify_quote_with_collateral_dates(make_quote_bytes(), collateral());

    // Then
    assert_eq!(
        result,
        VerificationResultWithCollateralDates::Verified {
            report: expected_report,
            collateral_dates: fixture_collateral_dates(),
        }
    );
}

#[rstest]
fn verify_quote_with_collateral_dates__should_give_the_same_expiry_as_verify_locally(
    #[values(&DSTACK_0_5_8, &DSTACK_0_6_5)] fixture: &AttestationFixture,
) {
    // Given
    set_timestamp_context(Duration::from_secs(fixture.valid_timestamp));
    let contract = TeeVerifier::default();
    let (quote, collateral) = (fixture.quote(), fixture.collateral());
    let report_data = ReportData::V1(ReportDataV1::new(
        fixture.p2p_tls_key().0,
        fixture.account_key().0,
    ));
    let AcceptedAttestation {
        attestation: VerifiedAttestation::Dstack(locally_verified),
        ..
    } = Attestation::Dstack(DstackAttestation::new(
        quote.clone(),
        collateral.clone(),
        fixture.tcb_info(),
    ))
    .verify_locally(
        report_data.into(),
        fixture.valid_timestamp,
        &[fixture.image_digest()],
        &[fixture.launcher_compose_digest()],
        &[fixture.measurements],
    )
    .expect("the fixture verifies locally")
    else {
        panic!("expected a Dstack attestation");
    };

    // When
    let result =
        contract.verify_quote_with_collateral_dates(QuoteBytes(Vec::from(quote)), collateral);

    // Then
    let VerificationResultWithCollateralDates::Verified {
        collateral_dates, ..
    } = result
    else {
        panic!("expected Verified, got {result:?}");
    };
    assert_eq!(
        locally_verified.expiry_timestamp_seconds,
        collateral_dates.earliest_expiration_date
    );
}

fn fixture_collateral_dates() -> CollateralDates {
    CollateralDates {
        earliest_issue_date: 1_526_899_510,
        latest_issue_date: 1_794_961_869,
        earliest_expiration_date: 1_797_553_190,
        qe_iden_earliest_issue_date: 1_526_899_510,
        qe_iden_latest_issue_date: 1_794_961_268,
        qe_iden_earliest_expiration_date: 1_797_553_268,
    }
}

const DAY: Duration = Duration::from_hours(24);
const TEN_YEARS: Duration = Duration::from_secs(10 * 365 * DAY.as_secs());

fn ten_years_after_fixture() -> Duration {
    Duration::from_secs(VALID_ATTESTATION_TIMESTAMP) + TEN_YEARS
}

fn invalid_quote() -> QuoteBytes {
    QuoteBytes(vec![0u8; 16])
}

/// The fixture collateral with a corrupted TCB Info signature.
fn mismatched_collateral() -> Collateral {
    let mut collateral = collateral();
    collateral.tcb_info_signature[0] ^= 1;
    collateral
}

/// The fixture collateral with a PCK CRL issuer chain that is not valid base64.
fn collateral_with_unparsable_pck_crl_issuer_chain() -> Collateral {
    Collateral {
        pck_crl_issuer_chain: String::from(
            "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
        ),
        ..collateral()
    }
}

/// The fixture collateral with a certificate that is not valid DER appended to
/// the TCB Info issuer chain.
fn collateral_with_garbage_certificate_in_tcb_info_issuer_chain() -> Collateral {
    let mut collateral = collateral();
    collateral
        .tcb_info_issuer_chain
        .push_str("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    collateral
}

#[rstest]
#[case::expired_collateral(ten_years_after_fixture(), make_quote_bytes(), collateral())]
#[case::invalid_quote(
    Duration::from_secs(VALID_ATTESTATION_TIMESTAMP),
    invalid_quote(),
    collateral()
)]
#[case::mismatched_collateral(
    Duration::from_secs(VALID_ATTESTATION_TIMESTAMP),
    make_quote_bytes(),
    mismatched_collateral()
)]
fn verify_quote_with_collateral_dates__should_reject_with_the_same_error_as_verify_quote(
    #[case] now: Duration,
    #[case] quote: QuoteBytes,
    #[case] collateral: Collateral,
) {
    // Given
    set_timestamp_context(now);
    let contract = TeeVerifier::default();
    let VerificationResult::Rejected(expected_error) =
        contract.verify_quote(quote.clone(), collateral.clone())
    else {
        panic!("verify_quote must reject this input");
    };

    // When
    let result = contract.verify_quote_with_collateral_dates(quote, collateral);

    // Then
    assert_eq!(
        result,
        VerificationResultWithCollateralDates::Rejected(expected_error)
    );
}

#[rstest]
#[case::unparsable_pck_crl_issuer_chain(collateral_with_unparsable_pck_crl_issuer_chain())]
#[case::garbage_certificate_in_tcb_info_issuer_chain(
    collateral_with_garbage_certificate_in_tcb_info_issuer_chain()
)]
fn verify_quote_with_collateral_dates__should_ignore_unverified_certificates(
    #[case] collateral: Collateral,
) {
    // Given
    set_valid_timestamp_context();
    let contract = TeeVerifier::default();
    let VerificationResult::Verified(expected_report) =
        contract.verify_quote(make_quote_bytes(), collateral.clone())
    else {
        panic!("verify_quote must accept this collateral");
    };

    // When
    let result = contract.verify_quote_with_collateral_dates(make_quote_bytes(), collateral);

    // Then
    assert_eq!(
        result,
        VerificationResultWithCollateralDates::Verified {
            report: expected_report,
            collateral_dates: fixture_collateral_dates(),
        }
    );
}

fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s)
        .expect("valid hex")
        .try_into()
        .expect("correct length")
}

/// The localnet guide (`docs/development/localnet/localnet.md`) calls `verify_quote` from the
/// command line. Its arguments are binary (borsh), so they are read from a committed
/// file.
///
/// This test keeps that file, `verify_quote_args.borsh`, correct: it rebuilds the
/// bytes `verify_quote(quote, collateral)` expects (both args, concatenated) and
/// checks they match the file. It fails if the `quote`/`collateral` fixtures change;
/// regenerate with:
///
///   UPDATE_FIXTURES=1 cargo test -p tee-verifier --test verify_quote verify_quote_args_fixture
#[test]
fn verify_quote_args_fixture__should_match_committed_file() {
    let mut expected = borsh::to_vec(&make_quote_bytes()).unwrap();
    expected.extend(borsh::to_vec(&collateral()).unwrap());
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/verify_quote_args.borsh"
    );
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::write(path, &expected).unwrap();
    }
    let committed = std::fs::read(path).unwrap();
    assert_eq!(
        expected, committed,
        "verify_quote_args.borsh is stale; regenerate with UPDATE_FIXTURES=1"
    );
}
