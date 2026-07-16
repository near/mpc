//! Sandbox tests for the async [`submit_participant_info`] flow that offloads DCAP
//! verification to a separate tee-verifier contract.
//!
//! Each test deploys the `test-tee-verifier` stub (returning a picked response
//! instead of running real `dcap-qvl`), votes it in as the trusted verifier, and
//! covers one branch of the promise chain: a Dstack submission spawns `verify_quote`
//! with [`MpcContract::resolve_verification`] chained as its callback, which settles
//! every outcome synchronously. When a submission fails, the top-level `submit` tx still
//! succeeds (it returned the chained promise); the error appears on one of the receipts.
#![allow(non_snake_case)]

use crate::sandbox::{
    common::SandboxTestSetup,
    utils::{
        consts::{ALL_PROTOCOLS, SUBMIT_PARTICIPANT_INFO_DEPOSIT},
        contract_build::stub_tee_verifier_contract,
        mpc_contract::{
            get_participant_attestation, submit_participant_info,
            submit_participant_info_with_deposit, total_gas_fee, vote_tee_verifier_change,
        },
    },
};
use mpc_contract::errors::TeeError;
use near_mpc_contract_interface::types as dtos;
use near_workspaces::{
    Account, Contract, Worker, network::Sandbox, result::ExecutionFinalResult, types::NearToken,
};
use test_tee_verifier_types::StubResponse;
use test_utils::attestation::{mock_dto_dstack_attestation, p2p_tls_key, verified_report};

/// Deposit attached to a Dstack submission: the flat storage fee, consumed on
/// success and fully refunded on failure.
const SUBMIT_DEPOSIT: NearToken = SUBMIT_PARTICIPANT_INFO_DEPOSIT;

/// Deploys the stub verifier with the given response, initializes it, and votes
/// it in as `mpc-contract`'s trusted verifier (all participants vote so the
/// change crosses threshold).
async fn deploy_and_trust_stub(
    worker: &Worker<Sandbox>,
    contract: &Contract,
    participants: &[Account],
    response: StubResponse,
) {
    let stub = worker
        .dev_deploy(stub_tee_verifier_contract())
        .await
        .unwrap();
    stub.call("new")
        .args_borsh(response)
        .transact()
        .await
        .unwrap()
        .into_result()
        .unwrap();

    // Unchecked against the stub; voters just need to agree on the same hash.
    let expected_code_hash = [7u8; 32];
    for account in participants {
        vote_tee_verifier_change(account, contract, stub.id(), expected_code_hash)
            .await
            .unwrap();
    }
}

async fn setup_with_stub(
    response: StubResponse,
    init_config: Option<dtos::InitConfig>,
) -> (Worker<Sandbox>, Contract, Account, NearToken) {
    let mut builder = SandboxTestSetup::builder().with_protocols(ALL_PROTOCOLS);
    if let Some(init_config) = init_config {
        builder = builder.with_init_config(init_config);
    }
    let SandboxTestSetup {
        worker,
        mpc_signer_accounts,
        contract,
        ..
    } = builder.build().await;
    deploy_and_trust_stub(&worker, &contract, &mpc_signer_accounts, response).await;

    let submitter = mpc_signer_accounts[0].clone();
    let balance_before = submitter.view_account().await.unwrap().balance;
    (worker, contract, submitter, balance_before)
}

async fn submit_dstack(submitter: &Account, contract: &Contract) -> ExecutionFinalResult {
    submit_participant_info_with_deposit(
        submitter,
        contract,
        &mock_dto_dstack_attestation(),
        &p2p_tls_key().into(),
        SUBMIT_DEPOSIT,
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
    // Given: no verifier voted in.
    let SandboxTestSetup {
        mpc_signer_accounts,
        contract,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    // When: a Dstack attestation is submitted.
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
    // Given: a verifier that always rejects.
    let (_worker, contract, submitter, balance_before) =
        setup_with_stub(StubResponse::Rejected("test rejection".to_string()), None).await;

    // When: a Dstack attestation is submitted.
    let result = submit_dstack(&submitter, &contract).await;

    // Then: the submission fails cleanly, reporting the verifier's rejection reason.
    assert_submission_failed_cleanly(
        &result,
        &contract,
        &submitter,
        balance_before,
        &TeeError::QuoteRejected {
            reason: "dcap verification failed: test rejection".to_string(),
        },
    )
    .await;
}

#[tokio::test]
async fn submit_participant_info__should_fail_and_store_nothing_on_verifier_crash() {
    // Given: a verifier that panics, so the verify_quote promise fails.
    let (_worker, contract, submitter, balance_before) =
        setup_with_stub(StubResponse::Panic, None).await;

    // When: a Dstack attestation is submitted.
    let result = submit_dstack(&submitter, &contract).await;

    // Then: the callback sees a failed promise, resolves to VerifierUnavailable,
    // refunds, and fails the submission in a separate receipt.
    assert_submission_failed_cleanly(
        &result,
        &contract,
        &submitter,
        balance_before,
        &TeeError::VerifierUnavailable,
    )
    .await;
}

#[tokio::test]
async fn submit_participant_info__should_refund_and_store_nothing_when_post_dcap_checks_fail() {
    // Given: a verifier that returns Verified, but an empty allowed-hash set, so the
    // post-DCAP checks in resolve_verification reject the (genuinely verified) quote.
    let (_worker, contract, submitter, balance_before) =
        setup_with_stub(StubResponse::Verified(verified_report()), None).await;

    // When: a Dstack attestation is submitted.
    let result = submit_dstack(&submitter, &contract).await;

    // Then: the callback's post-DCAP check rejects the (verified) quote. Asserted inline
    // rather than via assert_submission_failed_cleanly since the error is not a TeeError.
    let failures = result.failures();
    assert!(
        !failures.is_empty(),
        "expected the promise chain to fail on a receipt, got: {result:#?}"
    );
    let rendered = format!("{failures:?}");
    assert!(
        rendered.contains("the allowed mpc image hashes list is empty"),
        "expected the empty-allowlist rejection, got: {rendered}"
    );
    let stored = get_participant_attestation(&contract, &p2p_tls_key().into())
        .await
        .unwrap();
    assert!(stored.is_none(), "nothing should be stored on failure");
    assert_deposit_refunded(&submitter, balance_before, &result).await;
}

// TODO(#3787): un-ignore once the fixture allowlist setup lands; without it the
// post-DCAP check rejects the quote, so the store happy path can't run here yet.
#[ignore = "needs fixture allowlist setup to pass the post-DCAP checks; tracked in #3787"]
#[tokio::test]
async fn submit_participant_info__should_store_attestation_on_verified_quote() {
    // Given: a verifier that returns the report the real verifier would produce
    // for the fixture quote.
    let (_worker, contract, submitter, balance_before) =
        setup_with_stub(StubResponse::Verified(verified_report()), None).await;

    // When: a Dstack attestation is submitted.
    let result = submit_dstack(&submitter, &contract).await;

    // Then: every receipt in the verify_quote -> resolve_verification chain
    // succeeds, the attestation is stored, and the flat fee is consumed (not
    // refunded), so net spend is the fee plus gas.
    assert!(
        result.failures().is_empty(),
        "no receipt in the verify_quote -> resolve_verification promise chain may fail, got: {result:#?}"
    );
    let stored = get_participant_attestation(&contract, &p2p_tls_key().into())
        .await
        .unwrap();
    assert!(stored.is_some(), "a verified attestation must be stored");

    // net spend is at least the fee (the rest is gas); a refund would drop it
    // below the fee, proving the whole fee was consumed, not returned.
    let balance_after = submitter.view_account().await.unwrap().balance;
    let net_spent = balance_before.saturating_sub(balance_after);
    assert!(
        net_spent >= SUBMIT_DEPOSIT,
        "flat fee must be consumed, not refunded: spent {net_spent}, fee {SUBMIT_DEPOSIT}"
    );
}

// TODO(#3787): un-ignore once the fixture allowlist setup lands; without it the
// post-DCAP check fails fast and resolve_verification never reaches the heavy work
// needed to run it out of gas, so this re-tests the rejection path instead.
#[ignore = "needs fixture allowlist setup to reach the gas-heavy post-DCAP path; tracked in #3787"]
#[tokio::test]
async fn submit_participant_info__should_fail_and_store_nothing_when_resolve_verification_runs_out_of_gas()
 {
    // Given: a Verified stub and a resolve gas budget too small for the post-DCAP
    // work, so that callback OOGs and rolls back atomically.
    let init_config = dtos::InitConfig {
        resolve_verification_tera_gas: Some(1),
        ..Default::default()
    };
    let (_worker, contract, submitter, _balance_before) =
        setup_with_stub(StubResponse::Verified(verified_report()), Some(init_config)).await;

    // When: a Dstack attestation is submitted.
    let result = submit_dstack(&submitter, &contract).await;

    // Then: the OOG rolls the whole callback receipt back — the submission is reported
    // as failed and nothing is stored. No deposit-refund assertion: on an OOG the callback
    // dies before its `refund_to`, so the runtime returns the deposit to the predecessor
    // (the contract), never to the submitter, and nothing returns it later.
    assert!(
        !result.failures().is_empty(),
        "an OOG resolve_verification must fail the chain, got: {result:#?}"
    );
    let stored = get_participant_attestation(&contract, &p2p_tls_key().into())
        .await
        .unwrap();
    assert!(
        stored.is_none(),
        "nothing should be stored on an OOG resolve"
    );
}
