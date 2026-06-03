//! Integration test for the stateless `tee-verifier` contract.
//!
//! Calls `TeeVerifier::verify_quote` directly (no Promise round-trip)
//! with a real Dstack quote+collateral fixture taken from `test-utils`,
//! and asserts the returned `VerifiedReport` matches the fixture's known
//! value in full.

#![allow(non_snake_case)]

use near_sdk::{test_utils::VMContextBuilder, testing_env};
use std::time::Duration;
use tee_verifier::TeeVerifier;
use tee_verifier_interface::{
    Collateral, QuoteBytes, Report, TDReport10, TcbStatus, TcbStatusWithAdvisory, VerifiedReport,
};
use test_utils::attestation::{VALID_ATTESTATION_TIMESTAMP, collateral as collateral_json, quote};

fn make_collateral() -> Collateral {
    // `test_utils::attestation::collateral()` returns a `serde_json::Value`
    // matching `attestation::Collateral`'s JSON shape. We re-parse it
    // into the interface crate's mirror type by extracting the same
    // field names that `dcap_qvl::QuoteCollateralV3` uses.
    let v = collateral_json();
    Collateral {
        pck_crl_issuer_chain: v["pck_crl_issuer_chain"].as_str().unwrap().to_string(),
        root_ca_crl: hex::decode(v["root_ca_crl"].as_str().unwrap()).unwrap(),
        pck_crl: hex::decode(v["pck_crl"].as_str().unwrap()).unwrap(),
        tcb_info_issuer_chain: v["tcb_info_issuer_chain"].as_str().unwrap().to_string(),
        tcb_info: v["tcb_info"].as_str().unwrap().to_string(),
        tcb_info_signature: hex::decode(v["tcb_info_signature"].as_str().unwrap()).unwrap(),
        qe_identity_issuer_chain: v["qe_identity_issuer_chain"].as_str().unwrap().to_string(),
        qe_identity: v["qe_identity"].as_str().unwrap().to_string(),
        qe_identity_signature: hex::decode(v["qe_identity_signature"].as_str().unwrap()).unwrap(),
        pck_certificate_chain: v
            .get("pck_certificate_chain")
            .and_then(|s| s.as_str())
            .map(str::to_string),
    }
}

fn make_quote_bytes() -> QuoteBytes {
    QuoteBytes(Vec::from(quote()))
}

#[test]
fn verify_quote__should_return_up_to_date_td10_report_for_valid_fixture() {
    // Given
    let block_timestamp_ns = Duration::from_secs(VALID_ATTESTATION_TIMESTAMP).as_nanos() as u64;
    testing_env!(
        VMContextBuilder::new()
            .block_timestamp(block_timestamp_ns)
            .build()
    );
    let contract = TeeVerifier::default();
    let quote = make_quote_bytes();
    let collateral = make_collateral();

    // When
    let report = contract
        .verify_quote(quote, collateral)
        .expect("valid fixture should verify");

    // Then
    let expected = VerifiedReport {
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
                "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
            ),
            mr_config_id: hex_arr(
                "01cb9b2d6204f5e44238b75f69e3a3069550734c0d99ebdd3be507c238a261d8fa000000000000000000000000000000",
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
                "b598fde9491427341bc4683b75d10d3e36770af3a36a6954d8b6b7b22aa66358f13e1f172e51b7d6e6710d99a8d8532f",
            ),
            rt_mr2: hex_arr(
                "c812d42bfff1c75382e91a37c867ab117b97eb5e8d6797488928ea38e5fd38b5ed2f87d9613d392507f1c3af94657c93",
            ),
            rt_mr3: hex_arr(
                "b7662ac19c27af648a939be042684bbdb43bb3dddf4cd17bb21f4d455ab1926c6ee57038152fc46ddea392c47eb2af27",
            ),
            report_data: hex_arr(
                "00014ee5e70e861db29a95224e48a47c016ab03c61238333319af7614593cd155ba531073edd69921742beb1c510ff4339480000000000000000000000000000",
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
    assert_eq!(report, expected);
}

fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s)
        .expect("valid hex")
        .try_into()
        .expect("correct length")
}
