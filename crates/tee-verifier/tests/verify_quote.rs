//! Integration test for the stateless `tee-verifier` contract.
//!
//! Calls `TeeVerifier::verify_quote` directly (no Promise round-trip)
//! with a real Dstack quote+collateral fixture taken from `test-utils`,
//! and asserts that the returned `VerifiedReport` carries the
//! `UpToDate` TCB status and a TD10 report.

#![allow(non_snake_case)]

use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;
use std::time::Duration;
use tee_verifier::TeeVerifier;
use tee_verifier_interface::{Collateral, QuoteBytes};
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
    let report = contract.verify_quote(quote, collateral);

    // Then
    assert_eq!(report.status, "UpToDate");
    assert!(report.advisory_ids.is_empty());
    let td10 = report
        .report
        .as_td10()
        .expect("fixture is a TD10 attestation");
    // The fixture's report_data is 64 bytes; we only check shape, not exact contents,
    // because that's bound to the keys baked into the fixture.
    assert_eq!(td10.report_data.len(), 64);
    assert_eq!(td10.mr_td.len(), 48);
    assert_eq!(td10.rt_mr0.len(), 48);
    assert_eq!(td10.rt_mr3.len(), 48);
}
