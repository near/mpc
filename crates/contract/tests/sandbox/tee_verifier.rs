//! Sandbox tests for the async [`submit_participant_info`] flow, driving the real
//! `tee-verifier` (or no verifier):
//! - Rejected: real verifier with a malformed quote.
//! - Unavailable: a verifier account that was never deployed.
//!
//! The Verified verdict is covered in-process instead (`verify_and_store_dstack` under
//! a pinned clock): real `verify_quote` checks the quote against live block time, and the
//! sandbox clock can't be wound back to the fixture's validity window.
#![allow(non_snake_case)]

use crate::sandbox::{
    common::SandboxTestSetup,
    utils::{
        consts::ALL_PROTOCOLS,
        contract_build::tee_verifier_contract,
        mpc_contract::{
            get_participant_attestation, submit_participant_info, total_gas_fee,
            vote_tee_verifier_change,
        },
    },
};
use mpc_contract::errors::TeeError;
use near_mpc_contract_interface::types as dtos;
use near_workspaces::{
    Account, AccountId, Contract, Worker, network::Sandbox, result::ExecutionFinalResult,
    types::NearToken,
};
use test_utils::attestation::{mock_dto_dstack_attestation, p2p_tls_key};

async fn setup() -> SandboxTestSetup {
    SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await
}

/// Votes `verifier` in as `mpc-contract`'s trusted verifier (all participants vote
/// so the change crosses threshold).
async fn trust_verifier(contract: &Contract, participants: &[Account], verifier: &AccountId) {
    let expected_code_hash = [7u8; 32];
    for account in participants {
        vote_tee_verifier_change(account, contract, verifier, expected_code_hash)
            .await
            .unwrap();
    }
}

async fn deploy_and_trust_verifier(
    worker: &Worker<Sandbox>,
    contract: &Contract,
    participants: &[Account],
) {
    let verifier = worker.dev_deploy(tee_verifier_contract()).await.unwrap();
    trust_verifier(contract, participants, verifier.id()).await;
}

async fn submit_dstack(submitter: &Account, contract: &Contract) -> ExecutionFinalResult {
    submit_participant_info(
        submitter,
        contract,
        &mock_dto_dstack_attestation(),
        &p2p_tls_key().into(),
    )
    .await
    .unwrap()
}

/// Asserts a Dstack submission failed cleanly: a receipt failed carrying
/// `expected_error` (`fail_attestation_submission` panics in its own receipt), no
/// attestation was stored, and the deposit was refunded.
async fn assert_submission_failed_cleanly(
    result: &ExecutionFinalResult,
    contract: &Contract,
    submitter: &Account,
    balance_before: NearToken,
    expected_error: &TeeError,
) {
    let failures = result.failures();
    assert!(
        !failures.is_empty(),
        "expected the promise chain to fail on a receipt, got: {result:#?}"
    );
    // Substring-match: near-workspaces keeps `ExecutionOutcome.status`
    // `pub(crate)`, so the error is only reachable via the Debug dump.
    let rendered = format!("{failures:?}");
    let expected = expected_error.to_string();
    assert!(
        rendered.contains(&expected),
        "expected a receipt failure containing {expected:?}, got: {rendered}"
    );

    let stored = get_participant_attestation(contract, &p2p_tls_key().into())
        .await
        .unwrap();
    assert!(stored.is_none(), "nothing should be stored on failure");
    assert_deposit_refunded(submitter, balance_before, result).await;
}

/// Asserts the deposit was fully refunded: with nothing stored, the caller spends only gas.
async fn assert_deposit_refunded(
    account: &Account,
    balance_before: NearToken,
    result: &ExecutionFinalResult,
) {
    let balance_after = account.view_account().await.unwrap().balance;
    let net_spent = balance_before.saturating_sub(balance_after);
    assert_eq!(net_spent, total_gas_fee(result));
}

#[tokio::test]
async fn submit_participant_info__should_reject_dstack_when_verifier_not_configured() {
    // Given
    let SandboxTestSetup {
        mpc_signer_accounts,
        contract,
        ..
    } = setup().await;

    // When
    let result = submit_participant_info(
        &mpc_signer_accounts[0],
        &contract,
        &mock_dto_dstack_attestation(),
        &p2p_tls_key().into(),
    )
    .await
    .unwrap();

    // Then: it fails synchronously (before any cross-contract call), so the error
    // is on the top-level tx result, not a later receipt.
    let err = result
        .into_result()
        .expect_err("Dstack submit must fail when no verifier is configured")
        .to_string();
    let expected_panic = format!(
        "Smart contract panicked: {}",
        TeeError::VerifierNotConfigured
    );
    assert!(
        err.contains(&expected_panic),
        "expected {expected_panic:?}, got: {err}"
    );
    let stored = get_participant_attestation(&contract, &p2p_tls_key().into())
        .await
        .unwrap();
    assert!(stored.is_none(), "no attestation should be stored");
}

#[tokio::test]
async fn submit_participant_info__should_refund_and_store_nothing_on_verifier_rejection() {
    // Given
    let SandboxTestSetup {
        worker,
        mpc_signer_accounts,
        contract,
        ..
    } = setup().await;
    deploy_and_trust_verifier(&worker, &contract, &mpc_signer_accounts).await;
    let submitter = mpc_signer_accounts[0].clone();
    let balance_before = submitter.view_account().await.unwrap().balance;
    let mut attestation = mock_dto_dstack_attestation();
    let dtos::Attestation::Dstack(dstack) = &mut attestation else {
        panic!("fixture must be a Dstack attestation");
    };
    dstack.quote = dtos::HexVec(vec![0u8; 16]);

    // When
    let result =
        submit_participant_info(&submitter, &contract, &attestation, &p2p_tls_key().into())
            .await
            .unwrap();

    // Then
    assert_submission_failed_cleanly(
        &result,
        &contract,
        &submitter,
        balance_before,
        &TeeError::QuoteRejected {
            reason: String::new(),
        },
    )
    .await;
}

#[tokio::test]
async fn submit_participant_info__should_fail_and_store_nothing_when_verifier_unreachable() {
    // Given: a verifier account that was never deployed, so the verify_quote promise fails.
    let SandboxTestSetup {
        mpc_signer_accounts,
        contract,
        ..
    } = setup().await;
    let missing_verifier: AccountId = "nonexistent-verifier.near".parse().unwrap();
    trust_verifier(&contract, &mpc_signer_accounts, &missing_verifier).await;
    let submitter = mpc_signer_accounts[0].clone();
    let balance_before = submitter.view_account().await.unwrap().balance;

    // When
    let result = submit_dstack(&submitter, &contract).await;

    // Then
    assert_submission_failed_cleanly(
        &result,
        &contract,
        &submitter,
        balance_before,
        &TeeError::VerifierUnavailable,
    )
    .await;
}
