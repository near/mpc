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
        sandbox_mpc_contract::{SandboxMpcContract, SandboxMpcContractExt as _},
        transactions::{CallMpcContract as _, all_receipts_successful},
    },
};
use anyhow::Result;
use mpc_contract::{
    primitives::{
        participants::Participants,
        test_utils::bogus_ed25519_public_key,
        thresholds::{GovernanceThreshold, GovernanceThresholdParameters},
    },
    tee::test_utils::make_measurement,
};
use mpc_primitives::hash::{LauncherImageHash, NodeImageHash};
use near_mpc_contract_interface::types::{
    self as dtos, Attestation, CodeHashesVotes, LauncherHashVotes, MeasurementVotes,
    MockAttestation, Protocol,
};
use near_workspaces::Account;
use test_utils::attestation::{mock_expiring_at, p2p_tls_key};

/// Reshares to the first threshold of participants, so that the others depart, and returns the
/// new participants.
async fn reshare_to_first_threshold_participants(
    contract: &SandboxMpcContract,
    mpc_signer_accounts: &[Account],
) -> Result<Participants> {
    let participants: Participants =
        (&assert_running_return_participants(contract).await?).into_contract_type();
    let threshold = assert_running_return_threshold(contract).await;
    let remaining = usize::try_from(threshold.0)?;
    let new_participants = participants.subset(0..remaining);
    let new_threshold_parameters = GovernanceThresholdParameters::new(
        new_participants.clone(),
        GovernanceThreshold::new(threshold.0),
    )
    .unwrap();
    do_resharing(
        &mpc_signer_accounts[..remaining],
        contract,
        new_threshold_parameters,
        dtos::EpochId(6),
    )
    .await?;
    Ok(new_participants)
}

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

    let new_participants =
        reshare_to_first_threshold_participants(&contract, &mpc_signer_accounts).await?;

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

    let initial_participants_count = assert_running_return_participants(&contract)
        .await?
        .participants
        .len();

    // Insert an attestation from an outsider whose expiry is a few seconds away.
    let (stale_accounts, _) = gen_accounts(&worker, 1).await;
    let stale_account = &stale_accounts[0];
    let stale_tls_key: dtos::Ed25519PublicKey = p2p_tls_key().into();
    let block_info = worker.view_block().await?;
    let expiry_timestamp_seconds =
        block_info.timestamp() / 1_000_000_000 + ATTESTATION_EXPIRY_SECONDS;
    let expiring_attestation = Attestation::Mock(mock_expiring_at(expiry_timestamp_seconds));
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
    reshare_to_first_threshold_participants(&contract, &mpc_signer_accounts).await?;

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

/// Every departing participant leaves a pending vote in each MPC node and backup service TEE vote
/// collection. The promises the resharing spawns to drop them run with fixed gas, and the
/// resharing fails if any of them runs out of it.
#[tokio::test]
async fn reshare__should_drop_departed_participants_tee_votes_within_their_cleanup_gas()
-> Result<()> {
    // Given
    let SandboxTestSetup {
        worker: _worker,
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .with_sandbox_test_methods()
        .build()
        .await;
    let remaining = usize::try_from(assert_running_return_threshold(&contract).await.0)?;
    let code_hash = NodeImageHash::from([1; 32]);
    let launcher_hash = LauncherImageHash::from([2; 32]);
    let measurement = make_measurement(3);
    for account in &mpc_signer_accounts[remaining..] {
        let handle = account.call_mpc(contract.id());
        for result in [
            handle.vote_mpc_node_manifest_digest(code_hash).await?,
            handle.vote_add_launcher_hash(launcher_hash).await?,
            handle.vote_add_os_measurement(measurement.clone()).await?,
            handle.vote_backup_service_code_hash(code_hash).await?,
            handle
                .vote_add_backup_service_launcher_hash(launcher_hash)
                .await?,
            handle
                .vote_add_backup_service_os_measurement(measurement.clone())
                .await?,
        ] {
            all_receipts_successful(result)?;
        }
    }

    // When
    reshare_to_first_threshold_participants(&contract, &mpc_signer_accounts).await?;

    // Then
    let backup_service_votes: (CodeHashesVotes, LauncherHashVotes, MeasurementVotes) = contract
        .as_account()
        .view(contract.id(), "backup_service_tee_votes")
        .await?
        .json()?;
    assert_eq!(
        (
            contract.mpc_node_manifest_digest_votes().await?.value,
            contract.launcher_hash_votes().await?.value,
            contract.os_measurement_votes().await?.value,
            backup_service_votes,
        ),
        Default::default()
    );

    Ok(())
}
