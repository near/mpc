#![allow(non_snake_case)]

use crate::sandbox::{
    common::{
        SandboxTestSetup, build_sandbox_nodes, gen_accounts, prepay_and_submit_tee_attestations,
        sandbox_node,
    },
    utils::{
        interface::IntoContractType,
        mpc_contract::{
            assert_running_return_participants, assert_running_return_threshold, get_tee_accounts,
            prepay_and_submit_participant_info,
        },
        resharing_utils::do_resharing,
    },
};
use anyhow::Result;
use mpc_contract::primitives::{
    participants::Participants, test_utils::bogus_ed25519_public_key,
    thresholds::GovernanceThresholdParameters,
};
use near_mpc_contract_interface::types::{self as dtos, Attestation, MockAttestation, Protocol};
use test_utils::attestation::p2p_tls_key;

/// Integration test that validates the end-to-end behavior of the TEE attestation store
/// through a full resharing cycle.
///
/// This test:
/// 1. Sets up an initial participant set with TEE attestations
/// 2. Adds additional TEE attestations that do not belong to any participant
/// 3. Initiates a new resharing with a subset of the original participants
/// 4. Completes the resharing process by voting
/// 5. Verifies that after `vote_reshared` the contract returns to [`Running`] with the reduced set
/// 6. Confirms valid non-participant attestations remain in TEE storage: the post-resharing
///    `clean_invalid_attestations` sweep only evicts entries failing re-verification
///    (expired, stale docker/launcher/measurement whitelists), and mock [`Valid`]
///    attestations never fail re-verification.
#[tokio::test]
async fn reshare__should_leave_valid_non_participant_attestations_in_storage() -> Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .build()
        .await;

    // extract initial participants:
    let initial_participants = assert_running_return_participants(&contract).await?;
    let threshold = assert_running_return_threshold(&contract).await;
    let internal_initial_participants: Participants = (&initial_participants).into_contract_type();
    let mut expected_nodes =
        build_sandbox_nodes(&internal_initial_participants, &mpc_signer_accounts);

    // Verify TEE info for initial participants was added
    let nodes_with_tees = get_tee_accounts(&contract).await.unwrap();
    assert_eq!(nodes_with_tees, expected_nodes);

    let (mut env_non_participant_accounts, non_participants) = gen_accounts(&worker, 1).await;
    let non_participant_nodes =
        build_sandbox_nodes(&non_participants, &env_non_participant_accounts);
    prepay_and_submit_tee_attestations(
        &contract,
        &mut env_non_participant_accounts,
        &non_participant_nodes,
    )
    .await?;
    expected_nodes.extend(non_participant_nodes);

    let new_node = sandbox_node(&mpc_signer_accounts[0], bogus_ed25519_public_key());
    let attestation = Attestation::Mock(MockAttestation::Valid); // TODO(#1109): add TLS key
    let result = prepay_and_submit_participant_info(
        &mpc_signer_accounts[0],
        &contract,
        &attestation,
        &new_node.tls_public_key,
    )
    .await?;
    assert!(result.is_success());

    expected_nodes.insert(new_node);

    // Verify TEE info for prospective participants was added and TEE info for initial participants persists
    let initial_and_non_participants = get_tee_accounts(&contract).await.unwrap();
    assert_eq!(initial_and_non_participants, expected_nodes);

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
                participant_info.clone(),
                mpc_contract::primitives::participants::ParticipantId((*participant_id).into()),
            )
            .expect("Failed to insert participant");
    }

    let new_threshold_parameters = GovernanceThresholdParameters::new(
        new_participants.clone(),
        mpc_contract::primitives::thresholds::GovernanceThreshold::new(threshold.0),
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

    let final_participants: Participants =
        (&assert_running_return_participants(&contract).await?).into_contract_type();
    assert_eq!(final_participants, new_participants);

    // Verify TEE storage: valid attestations previously stored are still present — the
    // post-reshare `clean_invalid_attestations` sweep only evicts invalid / expired entries.
    let tee_participants_after_reshare = get_tee_accounts(&contract).await.unwrap();
    assert_eq!(tee_participants_after_reshare, expected_nodes);

    Ok(())
}

/// Companion to the test above: verifies that the post-resharing promise chain actually
/// invokes `clean_invalid_attestations` and evicts entries that fail re-verification.
/// [`verify()`] rejects attestations that are already expired at insert time, so this test
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
        .with_protocols(&[Protocol::CaitSith])
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
    let submit_result = prepay_and_submit_participant_info(
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
                participant_info.clone(),
                mpc_contract::primitives::participants::ParticipantId((*participant_id).into()),
            )
            .expect("Failed to insert participant");
    }
    let new_threshold_parameters = GovernanceThresholdParameters::new(
        new_participants,
        mpc_contract::primitives::thresholds::GovernanceThreshold::new(threshold.0),
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
            .any(|node| node.account_id == *stale_account.id()),
        "expired outsider attestation should have been evicted by the post-reshare sweep",
    );

    Ok(())
}
