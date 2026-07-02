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
//! - `resolve_verification` runs out of gas → its receipt rolls back atomically
//!   and the same ~200-block timeout cleans up (no half-committed state).
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
use test_utils::attestation::{mock_dto_dstack_attestation, p2p_tls_key, verified_report};

/// Blocks to fast-forward past the ~200-block yield-resume timeout so the
/// runtime fires `on_attestation_verified`'s timeout branch.
const YIELD_TIMEOUT_BLOCKS: u64 = 250;

/// Mirror of `test_tee_verifier::StubResponse`. Re-declared here (rather than
/// depending on the stub crate) so the test only needs its Borsh encoding to
/// initialize the deployed stub; the stub is a separate `#[near]` contract and
/// linking its crate into this test binary would collide on ABI symbols.
///
/// KEEP THE VARIANT ORDER IN SYNC with `test_tee_verifier::StubResponse`: Borsh
/// encodes an enum as a u8 discriminant equal to the declaration index, so a
/// reorder on either side silently misroutes the response. `stub_response_discriminants`
/// below pins the indices so a divergence fails loudly.
#[expect(clippy::large_enum_variant)]
#[derive(BorshSerialize)]
enum StubResponse {
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
async fn submit_participant_info__should_reject_dstack_when_verifier_not_configured() -> Result<()>
{
    // Given: a running contract with no verifier voted in.
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

    // Then: it fails synchronously with the VerifierNotConfigured error (the
    // early return in submit_dstack_attestation, before any yield is registered),
    // and nothing is stored. Assert the specific message so an unrelated failure
    // (gas, encoding) can't pass as success.
    let err = result
        .into_result()
        .expect_err("Dstack submit must fail when no verifier is configured")
        .to_string();
    assert!(
        err.contains("No TEE verifier is configured"),
        "expected VerifierNotConfigured, got: {err}"
    );
    let stored = get_participant_attestation(&contract, &tls_key()).await?;
    assert!(stored.is_none(), "no attestation should be stored");
    Ok(())
}

#[tokio::test]
async fn submit_participant_info__should_refund_and_store_nothing_on_verifier_rejection()
-> Result<()> {
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
    // is refunded. The rejection resolves in the verifier's response receipt (a
    // later receipt than the original call), so the outcome is observable in
    // state rather than on the original transaction's result.
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
async fn submit_participant_info__should_clean_up_on_verifier_crash() -> Result<()> {
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
    // Unlike the rejection test, the outer-tx result isn't asserted here: the
    // failure only resolves when the yield times out, which `near-workspaces`
    // does not surface on the original `transact()`, so we assert state instead.
    let _ = submit_participant_info_with_deposit(
        submitter,
        &contract,
        &dstack_attestation(),
        &tls_key(),
        NearToken::from_near(1),
    )
    .await?;
    worker.fast_forward(YIELD_TIMEOUT_BLOCKS).await?;

    // Then: nothing is stored, and the timeout cleanup actually committed: the
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

// TODO(#3730): un-ignore once the fixture allowlist setup lands. To make
// `resolve_verification` actually run out of gas, execution must reach the
// expensive RTMR3 replay inside `verify_post_dcap_and_store` before exhausting
// the 1 TGas budget. That requires the post-DCAP checks to get *past* the
// allowlist gate first, i.e. the contract must have the fixture's MPC image hash
// (`image_digest()`), launcher compose hash (`launcher_compose_digest()`), and
// measurements voted in, and the submitter must use the fixture keys so the
// report-data binding matches. With an empty allowlist (as here) the check
// fails fast and cheap, so `resolve_verification` completes at 1 TGas and this
// re-tests the rejection path instead. Shares that setup with the (also pending)
// Verified happy-path test.
#[ignore = "needs fixture allowlist setup to reach the gas-heavy post-DCAP path; see TODO(#3730)"]
#[tokio::test]
async fn submit_participant_info__should_clean_up_when_resolve_verification_runs_out_of_gas()
-> Result<()> {
    // Given: a contract configured with a `resolve_verification` gas budget far
    // too small to run the post-DCAP work and resume the yield. The stub returns
    // `Verified` so `resolve_verification` enters `verify_post_dcap_and_store`
    // (the heavy RTMR3-replay path), which then exhausts the 1 TGas budget and
    // rolls the whole receipt back. A `Rejected` response would not work here:
    // its branch is light enough to complete even at 1 TGas.
    let init_config = dtos::InitConfig {
        resolve_verification_tera_gas: Some(1),
        ..Default::default()
    };
    let SandboxTestSetup {
        worker,
        mpc_signer_accounts,
        contract,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .with_sandbox_test_methods()
        .with_init_config(init_config)
        .build()
        .await;
    deploy_and_trust_stub(
        &worker,
        &contract,
        &mpc_signer_accounts,
        StubResponse::Verified(verified_report()),
    )
    .await?;

    // When: a participant submits. The verifier answers, but `resolve_verification`
    // runs out of gas before `promise_yield_resume`, so its whole receipt (the
    // pending-entry removal and the refund included) rolls back and the yield is
    // never resumed.
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

    // Distinguish this path from the rejection test: because
    // `resolve_verification` rolled back rather than resuming, the pending entry
    // is still present here. The rejection path would have removed it already.
    assert!(
        has_pending_attestation(&contract, submitter.id()).await?,
        "pending entry must survive an OOG resolve_verification (cleanup is left to the timeout)"
    );

    // Advancing past the ~200-block window fires `on_attestation_verified`'s
    // timeout branch, which is what actually cleans up in this path.
    worker.fast_forward(YIELD_TIMEOUT_BLOCKS).await?;

    // Then: an out-of-gas `resolve_verification` is recovered like an unreachable
    // verifier: nothing stored, the pending entry cleaned up by the timeout
    // branch, and the deposit refunded. This is the guarantee that a partial
    // `resolve_verification` receipt cannot leave a refunded-but-still-pending
    // entry: the receipt is atomic, so the account is not wedged.
    let stored = get_participant_attestation(&contract, &tls_key()).await?;
    assert!(
        stored.is_none(),
        "nothing should be stored when resolve_verification runs out of gas"
    );
    assert!(
        !has_pending_attestation(&contract, submitter.id()).await?,
        "the pending entry must be cleaned up by the yield timeout after an OOG resolve_verification"
    );
    assert_deposit_refunded(submitter, balance_before).await?;
    Ok(())
}

/// Asserts the full 1 NEAR storage deposit was returned: the net spend since
/// `balance_before` is only gas, well under any fraction of the deposit.
async fn assert_deposit_refunded(account: &Account, balance_before: NearToken) -> Result<()> {
    let balance_after = account.view_account().await?.balance;
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
    Ok(())
}

/// Pins the Borsh discriminant of each [`StubResponse`] variant to its declaration
/// index. The deployed `test_tee_verifier::StubResponse` deserializes what this
/// mirror serializes, so a reorder on either side must fail loudly here rather
/// than silently misroute a response. `Verified` is index 0 by position (a
/// `VerifiedReport` fixture is not needed to guard the reorder that matters).
#[test]
fn stub_response_discriminants() {
    assert_eq!(
        borsh::to_vec(&StubResponse::Rejected(String::new())).unwrap()[0],
        1,
        "Rejected must be Borsh discriminant 1"
    );
    assert_eq!(
        borsh::to_vec(&StubResponse::Panic).unwrap()[0],
        2,
        "Panic must be Borsh discriminant 2"
    );
}
