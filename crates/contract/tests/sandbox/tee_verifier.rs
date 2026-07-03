//! Sandbox tests for the async [`submit_participant_info`] flow that offloads
//! DCAP verification to a separate tee-verifier contract.
//!
//! Each test deploys the `test-tee-verifier` stub, whose verify-quote returns a
//! response the test picks instead of running real `dcap-qvl`, votes it in as the
//! trusted verifier via [`vote_tee_verifier_change`], and then covers one branch
//! of the yield-resume flow:
//!
//! - verifier not configured → submission rejected, nothing stored.
//! - [`StubResponse::Rejected`] → submission fails, deposit refunded, nothing stored.
//! - no-verdict (stub panics) → the ~200-block yield timeout cleans up.
//! - out-of-gas resolve → the receipt rolls back atomically and the same timeout
//!   cleans up (no half-committed state).
#![allow(non_snake_case)]

use crate::sandbox::{
    common::SandboxTestSetup,
    utils::{
        consts::ALL_PROTOCOLS,
        contract_build::stub_tee_verifier_contract,
        mpc_contract::{
            get_participant_attestation, has_pending_attestation, submit_participant_info,
            submit_participant_info_with_deposit, vote_tee_verifier_change,
        },
    },
};
use mpc_contract::errors::TeeError;
use near_mpc_contract_interface::types as dtos;
use near_workspaces::{Account, Contract, Worker, network::Sandbox, types::NearToken};
use test_tee_verifier_types::StubResponse;
use test_utils::attestation::{mock_dto_dstack_attestation, p2p_tls_key, verified_report};

/// Blocks to fast-forward past the ~200-block yield-resume timeout so the
/// runtime fires the yield-callback's timeout branch.
const YIELD_TIMEOUT_BLOCKS: u64 = 250;

/// Deposit attached to a Dstack submission: covers storage on success, fully
/// refunded on failure.
const SUBMIT_DEPOSIT: NearToken = NearToken::from_near(1);

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
    let mut builder = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_sandbox_test_methods();
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

async fn submit_dstack(submitter: &Account, contract: &Contract) {
    let _ = submit_participant_info_with_deposit(
        submitter,
        contract,
        &mock_dto_dstack_attestation(),
        &p2p_tls_key().into(),
        SUBMIT_DEPOSIT,
    )
    .await
    .unwrap();
}

/// Asserts a failed submission left no stored attestation, no pending entry, and
/// refunded the deposit.
async fn assert_submission_cleaned_up(
    contract: &Contract,
    submitter: &Account,
    balance_before: NearToken,
) {
    let stored = get_participant_attestation(contract, &p2p_tls_key().into())
        .await
        .unwrap();
    assert!(stored.is_none(), "nothing should be stored on failure");
    assert!(
        !has_pending_attestation(contract, submitter.id()).await.unwrap(),
        "the pending entry must be cleaned up"
    );
    assert_deposit_refunded(submitter, balance_before).await;
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

    // Then: it fails synchronously (before any yield), so the error is on the tx
    // result.
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
    submit_dstack(&submitter, &contract).await;

    // Then: the submission is cleaned up. The rejection resolves in the verifier's
    // response receipt, so the outcome is observable in state, not the tx result.
    assert_submission_cleaned_up(&contract, &submitter, balance_before).await;
}

#[tokio::test]
async fn submit_participant_info__should_clean_up_on_verifier_crash() {
    // Given: a verifier that panics, so no resume lands.
    let (worker, contract, submitter, balance_before) =
        setup_with_stub(StubResponse::Panic, None).await;

    // When: a submission times out (no verdict within the yield window).
    submit_dstack(&submitter, &contract).await;
    worker.fast_forward(YIELD_TIMEOUT_BLOCKS).await.unwrap();

    // Then: the timeout cleans up. Guards the regression where cleanup was rolled
    // back by a panic in the same receipt, leaking the entry and wedging the account.
    assert_submission_cleaned_up(&contract, &submitter, balance_before).await;
}

// TODO(#3730): un-ignore once the fixture allowlist setup lands. To OOG,
// `resolve_verification` must reach the heavy RTMR3 replay, which needs the
// post-DCAP allowlist checks to pass first (fixture image/launcher hashes and
// measurements voted in, submitter using the fixture keys). With an empty
// allowlist the check fails fast and `resolve_verification` completes at 1 TGas,
// so this would re-test the rejection path.
#[ignore = "needs fixture allowlist setup to reach the gas-heavy post-DCAP path; tracked in #3730"]
#[tokio::test]
async fn submit_participant_info__should_clean_up_when_resolve_verification_runs_out_of_gas() {
    // Given: a Verified stub and a resolve gas budget too small for the post-DCAP
    // work, so that branch OOGs and rolls back. (Rejected is too light to OOG.)
    let init_config = dtos::InitConfig {
        resolve_verification_tera_gas: Some(1),
        ..Default::default()
    };
    let (worker, contract, submitter, balance_before) =
        setup_with_stub(StubResponse::Verified(verified_report()), Some(init_config)).await;

    // When: a submission is made; resolve rolls back rather than resuming.
    submit_dstack(&submitter, &contract).await;

    // Then: unlike the rejection path, the entry is still pending before the
    // timeout; the timeout then cleans up, proving an atomic rollback of a partial
    // resolve receipt cannot wedge the account.
    assert!(
        has_pending_attestation(&contract, submitter.id()).await.unwrap(),
        "pending entry must survive an OOG resolve_verification (cleanup is left to the timeout)"
    );
    worker.fast_forward(YIELD_TIMEOUT_BLOCKS).await.unwrap();
    assert_submission_cleaned_up(&contract, &submitter, balance_before).await;
}

/// Asserts the full 1 NEAR storage deposit was returned: the net spend is only
/// gas, well under any fraction of the deposit.
async fn assert_deposit_refunded(account: &Account, balance_before: NearToken) {
    let balance_after = account.view_account().await.unwrap().balance;
    // Raw subtraction (not `saturating_sub`): if the contract over-refunds so
    // `balance_after > balance_before`, this underflows and panics rather than
    // clamping to 0 and silently passing.
    let net_spent = balance_before.as_yoctonear() - balance_after.as_yoctonear();
    // Bound to the gas envelope, not the deposit: max gas (~0.03 NEAR at the
    // sandbox price) sits far below this ceiling, while any partial retention of
    // the 1 NEAR deposit (e.g. 0.5 NEAR) would exceed it and fail.
    let gas_ceiling = NearToken::from_millinear(50).as_yoctonear();
    assert!(
        net_spent < gas_ceiling,
        "deposit should be fully refunded (net spent {net_spent} yoctoNEAR should be gas-only, < {gas_ceiling})"
    );
}
