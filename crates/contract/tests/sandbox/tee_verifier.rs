//! Sandbox tests for the async [`submit_participant_info`] flow that offloads
//! DCAP verification to a separate tee-verifier contract.
//!
//! Each test deploys the `test-tee-verifier` stub, whose verify-quote returns a
//! response the test picks instead of running real `dcap-qvl`, votes it in as the
//! trusted verifier via [`vote_tee_verifier_change`], and then covers one branch
//! of the promise-chain flow.
//!
//! A Dstack submission spawns `verify_quote` on the trusted verifier with
//! [`MpcContract::resolve_verification`] chained as its callback. There is no
//! yield-resume and no timeout: [`resolve_verification`] settles every outcome
//! synchronously within the same chain.
//!
//! - verifier not configured → the submit tx fails synchronously with
//!   [`TeeError::VerifierNotConfigured`], nothing stored.
//! - [`StubResponse::Rejected`] → [`resolve_verification`] refunds the deposit and
//!   fires `fail_attestation_submission`, which panics in a separate receipt to
//!   fail the submitter's transaction; nothing stored.
//! - stub panics (verifier unreachable) → the callback observes a failed promise,
//!   resolves to [`TeeError::VerifierUnavailable`], and fails the same way.
//!
//! On failure the top-level submit call still returns its chained promise, so the
//! failure surfaces on the chain's receipt outcomes
//! ([`ExecutionFinalResult::failures`]), not on the top-level tx result.
#![allow(non_snake_case)]

use crate::sandbox::{
    common::SandboxTestSetup,
    utils::{
        consts::ALL_PROTOCOLS,
        contract_build::stub_tee_verifier_contract,
        mpc_contract::{
            get_participant_attestation, submit_participant_info,
            submit_participant_info_with_deposit, vote_tee_verifier_change,
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

/// Asserts a Dstack submission failed on the chain and left no committed state:
/// the failure surfaces on a receipt (`fail_attestation_submission` panics in its
/// own receipt), carries `expected_error`, nothing is stored, and the deposit is
/// refunded.
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

    // Then: resolve_verification refunds and fails the submission in a separate
    // receipt; the failure is on the chain, not the top-level tx result. The
    // stub wraps the reason in `VerifierError::DcapVerification`, whose Display
    // prefixes "dcap verification failed: ".
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
    // refunds, and fails the submission in a separate receipt. No timeout: the
    // outcome settles synchronously within the same chain.
    assert_submission_failed_cleanly(
        &result,
        &contract,
        &submitter,
        balance_before,
        &TeeError::VerifierUnavailable,
    )
    .await;
}

// TODO(#3738): un-ignore once the fixture allowlist setup lands. A Verified
// verdict routes through `verify_post_dcap_and_store`, whose allowlist checks
// (fixture image/launcher hashes and measurements voted in, submitter using the
// fixture keys) must pass before the attestation is stored. With an empty
// allowlist the post-DCAP check fails and the submission is rejected instead of
// stored, so the happy path cannot be exercised here yet.
#[ignore = "needs fixture allowlist setup to pass the post-DCAP checks; tracked in #3738"]
#[tokio::test]
async fn submit_participant_info__should_store_attestation_on_verified_quote() {
    // Given: a verifier that returns the report the real verifier would produce
    // for the fixture quote.
    let (_worker, contract, submitter, balance_before) =
        setup_with_stub(StubResponse::Verified(verified_report()), None).await;

    // When: a Dstack attestation is submitted.
    let result = submit_dstack(&submitter, &contract).await;

    // Then: the chain succeeds and the attestation is stored; storage is charged
    // and the excess deposit refunded (net spend is storage + gas, well under the
    // full deposit).
    assert!(
        result.failures().is_empty(),
        "the verified submission chain must succeed, got: {result:#?}"
    );
    let stored = get_participant_attestation(&contract, &p2p_tls_key().into())
        .await
        .unwrap();
    assert!(stored.is_some(), "a verified attestation must be stored");
    let balance_after = submitter.view_account().await.unwrap().balance;
    assert!(
        balance_after < balance_before,
        "storage must be charged from the attached deposit"
    );
}

// TODO(#3738): un-ignore once the fixture allowlist setup lands. To OOG,
// `resolve_verification` must reach the heavy RTMR3 replay in the post-DCAP
// checks, which needs the allowlist populated and the submitter using the fixture
// keys. With an empty allowlist the post-DCAP check fails fast and
// `resolve_verification` completes well under 1 TGas, re-testing the rejection
// path instead. Under the promise-chain model an OOG rolls the whole callback
// receipt back atomically: nothing is stored, the runtime refunds the attached
// deposit to the predecessor, and `fail_attestation_submission` never fires, so
// the chain still surfaces a failed receipt. No timeout is involved.
#[ignore = "needs fixture allowlist setup to reach the gas-heavy post-DCAP path; tracked in #3738"]
#[tokio::test]
async fn submit_participant_info__should_fail_and_store_nothing_when_resolve_verification_runs_out_of_gas()
 {
    // Given: a Verified stub and a resolve gas budget too small for the post-DCAP
    // work, so that callback OOGs and rolls back atomically.
    let init_config = dtos::InitConfig {
        resolve_verification_tera_gas: Some(1),
        ..Default::default()
    };
    let (_worker, contract, submitter, balance_before) =
        setup_with_stub(StubResponse::Verified(verified_report()), Some(init_config)).await;

    // When: a Dstack attestation is submitted.
    let result = submit_dstack(&submitter, &contract).await;

    // Then: the callback receipt fails wholesale, nothing is stored, and the
    // runtime refunds the attached deposit. Proves an OOG in resolve cannot commit
    // partial state.
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
    assert_deposit_refunded(&submitter, balance_before).await;
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
