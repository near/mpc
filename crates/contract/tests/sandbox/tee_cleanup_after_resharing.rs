#![allow(non_snake_case)]

use crate::sandbox::{
    common::{
        account_ed25519_public_key, build_sandbox_node_ids, gen_accounts, submit_tee_attestations,
        SandboxTestSetup,
    },
    utils::{
        interface::IntoContractType,
        mpc_contract::{
            assert_running_return_participants, assert_running_return_threshold, get_tee_accounts,
            submit_participant_info,
        },
        resharing_utils::do_resharing,
    },
};
use anyhow::Result;
use mpc_contract::{
    primitives::{
        participants::Participants, test_utils::bogus_ed25519_public_key,
        thresholds::ThresholdParameters,
    },
    tee::tee_state::NodeId,
};
use near_mpc_contract_interface::types::Curve;
use near_mpc_contract_interface::types::{self as dtos, Attestation, MockAttestation};
use test_utils::attestation::p2p_tls_key;

/// Integration test that validates the end-to-end behavior of the TEE attestation store
/// through a full resharing cycle.
///
/// This test:
/// 1. Sets up an initial participant set with TEE attestations
/// 2. Adds additional TEE attestations that do not belong to any participant
/// 3. Initiates a new resharing with a subset of the original participants
/// 4. Completes the resharing process by voting
/// 5. Verifies that after `vote_reshared` the contract returns to `Running` with the reduced set
/// 6. Confirms valid non-participant attestations remain in TEE storage: the post-resharing
///    `clean_invalid_attestations` sweep only evicts entries failing re-verification
///    (expired, stale docker/launcher/measurement whitelists), and mock `Valid`
///    attestations never fail re-verification.
#[tokio::test]
async fn reshare__should_leave_valid_non_participant_attestations_in_storage() -> Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_curves(&[Curve::Secp256k1])
        .build()
        .await;

    // extract initial participants:
    let initial_participants = assert_running_return_participants(&contract).await?;
    let threshold = assert_running_return_threshold(&contract).await;
    let internal_initial_participants: Participants = (&initial_participants).into_contract_type();
    let expected_node_ids =
        build_sandbox_node_ids(&internal_initial_participants, &mpc_signer_accounts);

    // Verify TEE info for initial participants was added
    let nodes_with_tees = get_tee_accounts(&contract).await.unwrap();
    assert_eq!(nodes_with_tees, expected_node_ids);

    // Add two prospective Participants
    // Note: this test fails if `vote_reshared` needs to clean up more than 3 attestations
    let (mut env_non_participant_accounts, non_participants) = gen_accounts(&worker, 1).await;
    let non_participant_uids =
        build_sandbox_node_ids(&non_participants, &env_non_participant_accounts);
    submit_tee_attestations(
        &contract,
        &mut env_non_participant_accounts,
        &non_participant_uids,
    )
    .await?;
    let mut expected_node_ids = expected_node_ids;
    expected_node_ids.extend(non_participant_uids);

    // add a new TEE quote for an existing participant, but with a different
    // signer key. The contract records `env::signer_account_pk()`, so the
    // account public key stored in the new attestation is the signer's real
    // key — match that here.
    let new_uid = NodeId {
        account_id: mpc_signer_accounts[0].id().clone(),
        tls_public_key: bogus_ed25519_public_key(),
        account_public_key: account_ed25519_public_key(&mpc_signer_accounts[0]),
    };
    let attestation = Attestation::Mock(MockAttestation::Valid); // TODO(#1109): add TLS key
    let result = submit_participant_info(
        &mpc_signer_accounts[0],
        &contract,
        &attestation,
        &new_uid.tls_public_key,
    )
    .await?;
    assert!(result.is_success());

    expected_node_ids.insert(new_uid);

    // Verify TEE info for prospective participants was added and TEE info for initial participants persists
    let initial_and_non_participants = get_tee_accounts(&contract).await.unwrap();
    assert_eq!(initial_and_non_participants, expected_node_ids);

    // Now, we do a resharing. We only retain `threshold` of the initial participants
    let mut new_participants = Participants::new();
    for (account_id, participant_id, participant_info) in initial_participants
        .participants
        .iter()
        .take(threshold.0 as usize)
    {
        new_participants
            .insert_with_id(
                account_id.clone(),
                mpc_contract::primitives::participants::ParticipantInfo {
                    url: participant_info.url.clone(),
                    tls_public_key: participant_info.tls_public_key.clone(),
                },
                mpc_contract::primitives::participants::ParticipantId((*participant_id).into()),
            )
            .expect("Failed to insert participant");
    }

    let post_reshare_participants = build_sandbox_node_ids(&new_participants, &mpc_signer_accounts);
    let new_threshold_parameters = ThresholdParameters::new(
        new_participants,
        mpc_contract::primitives::thresholds::Threshold::new(threshold.0),
    )
    .unwrap();

    let prospective_epoch_id = dtos::EpochId(6);

    do_resharing(
        &mpc_signer_accounts[..threshold.0 as usize],
        &contract,
        new_threshold_parameters,
        prospective_epoch_id,
    )
    .await?;

    // Verify contract is back to running state with new threshold
    let final_participants = assert_running_return_participants(&contract)
        .await
        .expect("Expected contract to be in Running state after resharing.");

    // Get current participants to compare
    let final_participants_node_ids = build_sandbox_node_ids(
        &(&final_participants).into_contract_type(),
        &mpc_signer_accounts,
    );
    // Verify only the new participants are current
    assert_eq!(final_participants_node_ids, post_reshare_participants);

    // Verify TEE storage: valid attestations previously stored are still present — the
    // post-reshare `clean_invalid_attestations` sweep only evicts invalid / expired entries.
    let tee_participants_after_reshare = get_tee_accounts(&contract).await.unwrap();
    assert_eq!(tee_participants_after_reshare, expected_node_ids);

    Ok(())
}

/// Companion to the test above: verifies that the post-resharing promise chain actually
/// invokes `clean_invalid_attestations` and evicts entries that fail re-verification.
/// `verify()` rejects attestations that are already expired at insert time, so this test
/// submits an attestation with an expiry a few seconds in the future and then fast-forwards
/// past it before triggering the reshare.
#[tokio::test]
async fn reshare__should_evict_expired_attestations_via_post_reshare_sweep() -> Result<()> {
    const ATTESTATION_EXPIRY_SECONDS: u64 = 5;
    const BLOCKS_TO_FAST_FORWARD: u64 = 100;

    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_curves(&[Curve::Secp256k1])
        .build()
        .await;

    let initial_participants = assert_running_return_participants(&contract).await?;
    let threshold = assert_running_return_threshold(&contract).await;
    let initial_participants_count = initial_participants.participants.len();

    // Insert an attestation from an outsider whose expiry is a few seconds away.
    let (stale_accounts, _) = gen_accounts(&worker, 1).await;
    let stale_account = &stale_accounts[0];
    let stale_tls_key: dtos::Ed25519PublicKey = p2p_tls_key().into();
    let block_info = worker.view_block().await?;
    let expiry_timestamp_seconds =
        block_info.timestamp() / 1_000_000_000 + ATTESTATION_EXPIRY_SECONDS;
    let expiring_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(expiry_timestamp_seconds),
        expected_measurements: None,
    });
    let submit_result = submit_participant_info(
        stale_account,
        &contract,
        &expiring_attestation,
        &stale_tls_key,
    )
    .await?;
    assert!(submit_result.is_success());
    assert_eq!(
        get_tee_accounts(&contract).await.unwrap().len(),
        initial_participants_count + 1
    );

    // Advance past the expiry before triggering the reshare so that the post-reshare
    // sweep sees the outsider entry as invalid.
    worker.fast_forward(BLOCKS_TO_FAST_FORWARD).await?;

    // Reshare to the threshold subset; this triggers the post-reshare cleanup promise.
    let mut new_participants = Participants::new();
    for (account_id, participant_id, participant_info) in initial_participants
        .participants
        .iter()
        .take(threshold.0 as usize)
    {
        new_participants
            .insert_with_id(
                account_id.clone(),
                mpc_contract::primitives::participants::ParticipantInfo {
                    url: participant_info.url.clone(),
                    tls_public_key: participant_info.tls_public_key.clone(),
                },
                mpc_contract::primitives::participants::ParticipantId((*participant_id).into()),
            )
            .expect("Failed to insert participant");
    }
    let new_threshold_parameters = ThresholdParameters::new(
        new_participants,
        mpc_contract::primitives::thresholds::Threshold::new(threshold.0),
    )
    .unwrap();
    do_resharing(
        &mpc_signer_accounts[..threshold.0 as usize],
        &contract,
        new_threshold_parameters,
        dtos::EpochId(6),
    )
    .await?;

    // The expired outsider attestation is evicted by the `clean_invalid_attestations`
    // promise spawned from `vote_reshared`.
    let tee_accounts_after_reshare = get_tee_accounts(&contract).await.unwrap();
    assert!(
        !tee_accounts_after_reshare
            .iter()
            .any(|uid| uid.account_id == stale_account.id().clone()),
        "expired outsider attestation should have been evicted by the post-reshare sweep",
    );

    Ok(())
}
