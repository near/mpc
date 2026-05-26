#![allow(non_snake_case)]

//! Contract-side reproduction of near/mpc#2121.
//!
//! When a node migrates A → B and then A goes offline long enough for its
//! PCCS collateral to age out (~7 days), the back-migration B → A fails at
//! `conclude_node_migration` because the contract's
//! [`reverify_participants`] check rejects the destination's now-stale
//! stored attestation with `InvalidParameters::InvalidTeeRemoteAttestation`.
//!
//! This test models the contract-side rejection mechanism. It does not
//! cover the node-side question of whether
//! `periodic_attestation_submission` fires fast enough on the destination's
//! restart to close the race window before `retry_conclude_onboarding`
//! drains its budget — that requires the running mpc-node binary and is
//! tracked separately.

use crate::sandbox::{
    common::{account_ed25519_public_key, SandboxTestSetup},
    utils::mpc_contract::submit_participant_info,
};
use anyhow::Result;
use mpc_contract::primitives::test_utils::bogus_ed25519_public_key;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    Attestation, Ed25519PublicKey, Keyset, MockAttestation, ProtocolContractState, Protocol,
};

/// Reproduces #2121's contract-side rejection.
///
/// 1. Default sandbox (2 participants, `MockAttestation::Valid` each).
/// 2. A0 submits a new attestation for a new TLS key with `expiry = now + 5s`.
///    This models the moment A0 restarts and submits an attestation whose
///    collateral is close to its TTL.
/// 3. A0 calls `start_node_migration` with destination = (its own current
///    signer pk, the new TLS key). In production this would be the back-
///    migration initiator pointing at the restarted A0; the contract only
///    requires the signer to be a current participant, so A0 itself stands
///    in for "B0 declaring A0 as the back-migration destination".
/// 4. `worker.fast_forward()` past the 5-second expiry — simulates the
///    PCCS collateral aging out while A0 was offline / between submissions.
/// 5. A0 calls `conclude_node_migration` with the current keyset.
/// 6. Assert the call returns `InvalidTeeRemoteAttestation`. The
///    rejection happens inside `reverify_participants` because the
///    destination's TLS-key-keyed stored attestation is now past its
///    expiry.
#[tokio::test]
async fn conclude_node_migration__rejects_when_destination_attestation_is_stale() -> Result<()> {
    const ATTESTATION_EXPIRY_SECONDS: u64 = 5;
    const BLOCKS_TO_FAST_FORWARD: u64 = 100;

    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    let a0_account = &mpc_signer_accounts[0];
    let a0_signer_pk = account_ed25519_public_key(a0_account);

    // Fresh TLS key for the back-migration destination. Models A0's
    // node binding a new TLS key after restart (the `MPC_SECRET_STORE_KEY`
    // is fresh, so the derived P2P key is new).
    let destination_tls_key: Ed25519PublicKey = bogus_ed25519_public_key().into();

    // Submit an attestation for the new TLS key with a short expiry. The
    // submission itself succeeds because the attestation is still valid
    // at submit time (`now + 5s` is in the future).
    let block = worker.view_block().await?;
    let expiry_secs = block.timestamp() / 1_000_000_000 + ATTESTATION_EXPIRY_SECONDS;
    let expiring = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(expiry_secs),
        expected_measurements: None,
    });
    let submit = submit_participant_info(a0_account, &contract, &expiring, &destination_tls_key)
        .await?;
    assert!(
        submit.is_success(),
        "submit_participant_info should accept a not-yet-expired attestation, got: {submit:?}"
    );

    // Start the migration: destination signer_pk matches A0's current pk so
    // the `expected_signer_pk == signer_pk` check inside
    // conclude_node_migration passes. (We want the test to fail on the TEE
    // attestation check, not on signer mismatch.)
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
        .call(contract.id(), method_names::START_NODE_MIGRATION)
        .args_json(start_args)
        .max_gas()
        .transact()
        .await?
        .into_result()
        .expect("start_node_migration should succeed");

    // Fast-forward past the attestation expiry. Now the stored
    // attestation under `destination_tls_key` is no longer valid by the
    // contract's current_time_seconds.
    worker.fast_forward(BLOCKS_TO_FAST_FORWARD).await?;

    // Fetch the keyset that conclude_node_migration must echo back.
    let state: ProtocolContractState = contract.view(method_names::STATE).await?.json()?;
    let keyset: Keyset = match state {
        ProtocolContractState::Running(r) => r.keyset,
        other => panic!("expected Running state, got: {other:?}"),
    };

    // Call conclude_node_migration. This is where the contract calls
    // `reverify_participants` on the destination NodeId, which looks up
    // `stored_attestations[destination_tls_key]` and re-verifies — the
    // now-expired attestation makes it return `TeeQuoteStatus::Invalid`,
    // and conclude_node_migration returns InvalidTeeRemoteAttestation.
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
