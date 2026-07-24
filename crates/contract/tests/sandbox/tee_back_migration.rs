#![allow(non_snake_case)]

//! Contract-side coverage for near/mpc#2121.
//!
//! Two tests, sharing a setup helper:
//!
//! * `conclude_node_migration__rejects_when_destination_attestation_is_stale`
//!   reproduces the failure: an attestation is submitted with a near-future
//!   expiry, time fast-forwards past it, and `conclude_node_migration`
//!   returns `InvalidTeeRemoteAttestation` via `reverify_participants`.
//!
//! * `conclude_node_migration__succeeds_when_destination_submits_fresh_attestation_before_conclude`
//!   demonstrates the recovery path. Same setup, but the destination
//!   submits a fresh attestation for the same TLS key before calling
//!   conclude. This is what a fixed node should do in
//!   `execute_onboarding` before entering `retry_conclude_onboarding`.
//!
//! Both tests model only the contract-layer behaviour; the node-side race
//! between `periodic_attestation_submission` and
//! `retry_conclude_onboarding` requires the running mpc-node binary and is
//! tracked separately.

use crate::sandbox::{
    common::{account_ed25519_public_key, SandboxTestSetup},
    utils::mpc_contract::submit_participant_info,
};
use anyhow::Result;
use mpc_contract::primitives::test_utils::bogus_ed25519_public_key;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    Attestation, Ed25519PublicKey, Keyset, MockAttestation, Protocol, ProtocolContractState,
};
use near_workspaces::{Account, Contract};

const ATTESTATION_EXPIRY_SECONDS: u64 = 5;
const BLOCKS_TO_FAST_FORWARD: u64 = 100;

/// Shared setup for both back-migration tests. After this returns:
///   - The contract is in `Running` state with the default participant set.
///   - A0 has submitted an expiring attestation for a new TLS key.
///   - `start_node_migration` has been called by A0 with that TLS key as
///     the destination.
///   - Block time has been advanced past the expiry, so the stored
///     attestation under `destination_tls_key` is now stale by the
///     contract's `current_time_seconds`.
///
/// Returns `(a0_account, contract, destination_tls_key, keyset)` — the
/// last three are what each test needs to drive the final
/// `conclude_node_migration` call.
async fn setup_stale_back_migration(
    setup: &SandboxTestSetup,
) -> Result<(Account, Contract, Ed25519PublicKey, Keyset)> {
    let a0_account = setup.mpc_signer_accounts[0].clone();
    let a0_signer_pk = account_ed25519_public_key(&a0_account);
    let destination_tls_key: Ed25519PublicKey = bogus_ed25519_public_key();

    let block = setup.worker.view_block().await?;
    let expiry_secs = block.timestamp() / 1_000_000_000 + ATTESTATION_EXPIRY_SECONDS;
    let expiring = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(expiry_secs),
        expected_measurements: None,
    });
    let submit = submit_participant_info(
        &a0_account,
        &setup.contract,
        &expiring,
        &destination_tls_key,
    )
    .await?;
    assert!(
        submit.is_success(),
        "submit_participant_info should accept a not-yet-expired attestation, got: {submit:?}"
    );

    let start_args = serde_json::json!({
        "destination_node_info": {
            "signer_account_pk": a0_signer_pk,
            "destination_node_info": {
                "url": "https://localhost:80",
                "tls_public_key": destination_tls_key,
            }
        }
    });
    a0_account
        .call(setup.contract.id(), method_names::START_NODE_MIGRATION)
        .args_json(start_args)
        .max_gas()
        .transact()
        .await?
        .into_result()
        .expect("start_node_migration should succeed");

    setup.worker.fast_forward(BLOCKS_TO_FAST_FORWARD).await?;

    let state: ProtocolContractState = setup.contract.view(method_names::STATE).await?.json()?;
    let keyset: Keyset = match state {
        ProtocolContractState::Running(r) => r.keyset,
        other => panic!("expected Running state, got: {other:?}"),
    };

    Ok((
        a0_account,
        setup.contract.clone(),
        destination_tls_key,
        keyset,
    ))
}

/// Reproduces #2121's contract-side rejection.
///
/// After `setup_stale_back_migration` (which submits an expiring attestation,
/// starts the migration, and fast-forwards past the expiry), call
/// `conclude_node_migration` directly. The contract's `reverify_participants`
/// finds the now-stale attestation under `destination_tls_key` and rejects
/// with `InvalidTeeRemoteAttestation`.
#[tokio::test]
async fn conclude_node_migration__rejects_when_destination_attestation_is_stale() -> Result<()> {
    let setup = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;
    let (a0_account, contract, _destination_tls_key, keyset) =
        setup_stale_back_migration(&setup).await?;

    let conclude = a0_account
        .call(contract.id(), method_names::CONCLUDE_NODE_MIGRATION)
        .args_json(serde_json::json!({ "keyset": keyset }))
        .max_gas()
        .transact()
        .await?;

    let err = conclude
        .into_result()
        .expect_err("conclude_node_migration must reject a stale destination attestation");
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("InvalidTeeRemoteAttestation")
            || err_str.contains("destination node TEE quote is invalid"),
        "expected InvalidTeeRemoteAttestation, got: {err_str}"
    );

    Ok(())
}

/// Demonstrates the recovery path for #2121: if the destination submits a
/// fresh attestation for the same TLS key before calling
/// `conclude_node_migration`, the contract accepts the conclude.
///
/// This is what a fixed node should do in `execute_onboarding` before
/// entering `retry_conclude_onboarding` — check whether its on-chain
/// attestation is valid, and submit a fresh one if not. Pairs with the
/// companion `_rejects_when_destination_attestation_is_stale` test which
/// shows the failure mode this recovery closes.
#[tokio::test]
async fn conclude_node_migration__succeeds_when_destination_submits_fresh_attestation_before_conclude(
) -> Result<()> {
    let setup = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;
    let (a0_account, contract, destination_tls_key, keyset) =
        setup_stale_back_migration(&setup).await?;

    // Recovery step — the destination submits a fresh attestation for the
    // same TLS key, overwriting the stale one in `tee_state`. After this,
    // `reverify_participants` returns `Valid` at conclude time.
    let fresh = Attestation::Mock(MockAttestation::Valid);
    let resubmit =
        submit_participant_info(&a0_account, &contract, &fresh, &destination_tls_key).await?;
    assert!(
        resubmit.is_success(),
        "fresh attestation resubmission should succeed, got: {resubmit:?}"
    );

    let conclude = a0_account
        .call(contract.id(), method_names::CONCLUDE_NODE_MIGRATION)
        .args_json(serde_json::json!({ "keyset": keyset }))
        .max_gas()
        .transact()
        .await?;
    let result = conclude.into_result();
    assert!(
        result.is_ok(),
        "conclude_node_migration should succeed after fresh attestation resubmission, got: {result:?}"
    );

    Ok(())
}
