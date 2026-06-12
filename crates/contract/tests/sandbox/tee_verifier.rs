//! Sandbox tests for the async `submit_participant_info` flow that offloads DCAP
//! verification to a separate `tee-verifier` contract.
//!
//! These deploy the `test-tee-verifier` stub (which returns a test-chosen
//! `verify_quote` answer instead of running real `dcap-qvl`) and point
//! `mpc-contract` at it via `vote_tee_verifier_change`, then exercise each
//! resolution branch of the yield-resume flow:
//!
//! - verifier not configured → submission rejected, nothing stored.
//! - `Rejected` → submission fails, deposit refunded, no stored attestation.
//! - no-verdict (stub panics) → the ~200-block yield timeout cleans up.
//!
//! The `Verified` + post-DCAP-pass path (attestation stored) additionally needs
//! a stub report matching the fixture's post-DCAP expectations; it is a planned
//! follow-up once the off-chain report helper is wired into the sandbox harness.
//! The post-DCAP logic itself is unit-tested in `mpc-attestation`.
//!
//! They require the cross-contract runtime, so they live in sandbox rather than
//! the in-process tests. The WASM build needs the contract toolchain; these run
//! in CI.
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
use anyhow::Result;
use borsh::BorshSerialize;
use near_mpc_contract_interface::types::{self as dtos, Attestation};
use near_workspaces::{Account, Contract, Worker, network::Sandbox, types::NearToken};
use test_utils::attestation::{mock_dto_dstack_attestation, p2p_tls_key};

/// Blocks to fast-forward past the ~200-block yield-resume timeout so the
/// runtime fires `on_attestation_verified`'s timeout branch.
const YIELD_TIMEOUT_BLOCKS: u64 = 250;

/// Mirror of `test_tee_verifier::StubResponse`. Re-declared here (rather than
/// depending on the stub crate) so the test only needs its Borsh encoding to
/// initialize the deployed stub.
#[expect(clippy::large_enum_variant)]
#[derive(BorshSerialize)]
enum StubResponse {
    // The Verified branch is exercised by the (deferred) post-DCAP-pass test; it
    // is part of the stub's wire contract, so keep the variant even though no
    // current test constructs it.
    #[expect(dead_code)]
    Verified(tee_verifier_interface::VerifiedReport),
    Rejected(String),
    Panic,
}

/// Deploys the stub verifier with the given response, initializes it, and votes
/// it in as `mpc-contract`'s trusted verifier (all participants vote so the
/// change crosses threshold).
async fn deploy_and_trust_stub(
    worker: &Worker<Sandbox>,
    contract: &Contract,
    participants: &[Account],
    response: StubResponse,
) -> Result<Contract> {
    let stub = worker.dev_deploy(stub_tee_verifier_contract()).await?;
    stub.call("new")
        .args_borsh(response)
        .transact()
        .await?
        .into_result()?;

    // The contract only consumes `candidate_account_id`; the hash is a voter
    // commitment, so any agreed value works for the test.
    let expected_code_hash = [7u8; 32];
    for account in participants {
        vote_tee_verifier_change(account, contract, stub.id(), expected_code_hash).await?;
    }
    Ok(stub)
}

fn dstack_attestation() -> Attestation {
    mock_dto_dstack_attestation()
}

fn tls_key() -> dtos::Ed25519PublicKey {
    p2p_tls_key().into()
}

#[tokio::test]
async fn submit_participant_info__rejects_dstack_when_verifier_not_configured() -> Result<()> {
    // Given: a running contract with no verifier voted in (placeholder).
    let SandboxTestSetup {
        mpc_signer_accounts,
        contract,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    // When: a participant submits a Dstack attestation.
    let result = submit_participant_info(
        &mpc_signer_accounts[0],
        &contract,
        &dstack_attestation(),
        &tls_key(),
    )
    .await?;

    // Then: it is rejected (no verifier configured) and nothing is stored.
    assert!(
        result.is_failure(),
        "Dstack submit must fail when no verifier is configured: {result:#?}"
    );
    let stored = get_participant_attestation(&contract, &tls_key()).await?;
    assert!(stored.is_none(), "no attestation should be stored");
    Ok(())
}

#[tokio::test]
async fn submit_participant_info__refunds_and_stores_nothing_on_verifier_rejection() -> Result<()> {
    // Given: a contract whose trusted verifier always rejects.
    let SandboxTestSetup {
        worker,
        mpc_signer_accounts,
        contract,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_sandbox_test_methods()
        .build()
        .await;
    deploy_and_trust_stub(
        &worker,
        &contract,
        &mpc_signer_accounts,
        StubResponse::Rejected("test rejection".to_string()),
    )
    .await?;

    // When: a participant submits a Dstack attestation with a 1 NEAR deposit.
    let submitter = &mpc_signer_accounts[0];
    let balance_before = submitter.view_account().await?.balance;
    let _ = submit_participant_info_with_deposit(
        submitter,
        &contract,
        &dstack_attestation(),
        &tls_key(),
        NearToken::from_near(1),
    )
    .await?;

    // Then: nothing is stored, the pending entry is cleaned up, and the deposit
    // is refunded. (The rejection resolves in the yield-resume receipt, not the
    // original call, so we assert observable state rather than the outer tx flag.)
    let stored = get_participant_attestation(&contract, &tls_key()).await?;
    assert!(stored.is_none(), "a rejected quote must not be stored");
    assert!(
        !has_pending_attestation(&contract, submitter.id()).await?,
        "the pending entry must be cleaned up on rejection"
    );
    assert_deposit_refunded(submitter, balance_before).await?;
    Ok(())
}

#[tokio::test]
async fn submit_participant_info__cleans_up_on_verifier_crash() -> Result<()> {
    // Given: a contract whose trusted verifier panics (no verdict).
    let SandboxTestSetup {
        worker,
        mpc_signer_accounts,
        contract,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_sandbox_test_methods()
        .build()
        .await;
    deploy_and_trust_stub(
        &worker,
        &contract,
        &mpc_signer_accounts,
        StubResponse::Panic,
    )
    .await?;

    // When: a participant submits, the verifier crashes (no resume lands), and
    // the chain advances past the ~200-block yield timeout so the runtime fires
    // `on_attestation_verified`'s timeout branch.
    let submitter = &mpc_signer_accounts[0];
    let balance_before = submitter.view_account().await?.balance;
    let _ = submit_participant_info_with_deposit(
        submitter,
        &contract,
        &dstack_attestation(),
        &tls_key(),
        NearToken::from_near(1),
    )
    .await?;
    worker.fast_forward(YIELD_TIMEOUT_BLOCKS).await?;

    // Then: nothing is stored, and the timeout cleanup actually committed — the
    // pending entry is gone and the deposit refunded. (Guards the regression
    // where the cleanup was rolled back by a panic in the same receipt, leaking
    // the entry and locking the account out of resubmitting.)
    let stored = get_participant_attestation(&contract, &tls_key()).await?;
    assert!(
        stored.is_none(),
        "nothing should be stored when the verifier crashes"
    );
    assert!(
        !has_pending_attestation(&contract, submitter.id()).await?,
        "the pending entry must be cleaned up after the yield timeout"
    );
    assert_deposit_refunded(submitter, balance_before).await?;
    Ok(())
}

/// Asserts the 1 NEAR storage deposit was returned: the net spend since
/// `balance_before` is well under 1 NEAR (only gas), rather than the full
/// deposit being retained by the contract.
async fn assert_deposit_refunded(account: &Account, balance_before: NearToken) -> Result<()> {
    let balance_after = account.view_account().await?.balance;
    let net_spent = balance_before.saturating_sub(balance_after);
    assert!(
        net_spent < NearToken::from_near(1),
        "deposit should be refunded (net spent {net_spent} should be < 1 NEAR, gas only)"
    );
    Ok(())
}
