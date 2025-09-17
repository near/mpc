pub mod common;
use anyhow::Result;
use attestation::attestation::{Attestation, MockAttestation};
use near_workspaces::{Account, Contract};
use serde_json::json;

use common::{
    assert_running_return_participants, check_call_success, check_call_success_all_receipts,
    gen_accounts, get_tee_accounts, init_env_secp256k1, submit_participant_info,
    submit_tee_attestations,
};
use mpc_contract::{
    primitives::{
        domain::DomainId,
        key_state::EpochId,
        participants::Participants,
        test_utils::bogus_ed25519_near_public_key,
        thresholds::{Threshold, ThresholdParameters},
    },
    state::ProtocolContractState,
    tee::tee_state::NodeUid,
};

/// Integration test that validates the complete E2E flow of TEE cleanup after resharing.
///
/// This test:
/// 1. Sets up an initial participant set with TEE attestations
/// 2. Adds additional TEE participants (simulating stale data)
/// 3. Initiates a new resharing with a subset of the original participants
/// 4. Completes the resharing process by voting
/// 5. Verifies that vote_reshared triggered cleanup of stale TEE attestations
/// 6. Confirms only the new participant set remains in TEE state
#[tokio::test]
async fn test_tee_cleanup_after_full_resharing_flow() -> Result<()> {
    let (worker, contract, mut env_accounts, _) = init_env_secp256k1(1).await;

    // sanity check: assert we don't have any tee information to begin with
    let initial_tee_participants = get_tee_accounts(&contract).await.unwrap();
    assert!(initial_tee_participants.is_empty());

    // extract initial participants:
    let initial_participants = assert_running_return_participants(&contract).await?;
    let expected_node_uids = initial_participants.get_node_uids();

    // submit attestations
    submit_tee_attestations(&contract, &mut env_accounts, &expected_node_uids).await?;

    // Verify TEE info for initial participants was added
    let nodes_with_tees = get_tee_accounts(&contract).await.unwrap();
    assert_eq!(nodes_with_tees, expected_node_uids);

    // Add two prospective Participants
    // Note: this test fails if `vote_reshared` needs to clean up more than 3 attestations
    let (mut env_non_participant_accounts, non_participants) = gen_accounts(&worker, 1).await;
    let non_participant_uids = non_participants.get_node_uids();
    submit_tee_attestations(
        &contract,
        &mut env_non_participant_accounts,
        &non_participant_uids,
    )
    .await?;
    let mut expected_node_uids = expected_node_uids;
    expected_node_uids.extend(non_participant_uids);

    // add a new TEE quote for an existing participant, but with a different signer key
    let new_uid = NodeUid {
        account_id: env_accounts[0].id().clone(),
        tls_public_key: bogus_ed25519_near_public_key(),
    };
    let attestation = Attestation::Mock(MockAttestation::Valid); // todo #1109, add TLS key.
    submit_participant_info(
        &env_accounts[0],
        &contract,
        &attestation,
        &new_uid.tls_public_key,
    )
    .await?;

    expected_node_uids.insert(new_uid);

    // Verify TEE info for prospective participants was added and TEE info for initial participants persists
    let initial_and_non_participants = get_tee_accounts(&contract).await.unwrap();
    assert_eq!(initial_and_non_participants, expected_node_uids);

    // Now, we do a resharing. We only retain two of the three initial participants
    let mut new_participants = Participants::new();
    for (account_id, participant_id, participant_info) in
        initial_participants.participants().iter().take(2)
    {
        new_participants
            .insert_with_id(
                account_id.clone(),
                participant_info.clone(),
                participant_id.clone(),
            )
            .expect("Failed to insert participant");
    }

    let expected_tee_post_resharing = new_participants.get_node_uids();
    let new_threshold_parameters =
        ThresholdParameters::new(new_participants, Threshold::new(2)).unwrap();

    let prospective_epoch_id = EpochId::new(6);

    do_resharing(
        &env_accounts[..2],
        &contract,
        new_threshold_parameters,
        prospective_epoch_id,
        &[DomainId(0)],
    )
    .await?;

    // Verify contract is back to running state with new threshold
    let final_participants = assert_running_return_participants(&contract)
        .await
        .expect("Expected contract to be in Running state after resharing.");

    // Get current participants to compare
    let final_participants_node_uids = final_participants.get_node_uids();
    // Verify only the new participants remain
    assert_eq!(final_participants_node_uids, expected_tee_post_resharing);
    // Verify TEE participants are properly cleaned up
    let tee_participants_after_cleanup = get_tee_accounts(&contract).await.unwrap();

    // Verify that the remaining TEE participants match exactly the new contract participants
    assert_eq!(tee_participants_after_cleanup, expected_tee_post_resharing);

    Ok(())
}

async fn do_resharing(
    remaining_accounts: &[Account],
    contract: &Contract,
    new_threshold_parameters: ThresholdParameters,
    prospective_epoch_id: EpochId,
    domain_ids: &[DomainId],
) -> Result<()> {
    // vote for new parameters
    for account in remaining_accounts {
        check_call_success(
            account
                .call(contract.id(), "vote_new_parameters")
                .args_json(json!({
                    "prospective_epoch_id": prospective_epoch_id,
                    "proposal": new_threshold_parameters,
                }))
                .max_gas()
                .transact()
                .await?,
        );
    }

    // Verify contract is now in resharing state
    let state: ProtocolContractState = contract.view("state").await?.json()?;
    let ProtocolContractState::Resharing(resharing_state) = state else {
        panic!("Expected contract to be in Resharing state after voting");
    };

    for domain_id in domain_ids {
        let key_event_id = json!({
            "epoch_id": prospective_epoch_id.get(),
            "domain_id": domain_id.0,
            "attempt_id": 0,
        });

        let leader = remaining_accounts
            .iter()
            .min_by_key(|a| {
                resharing_state
                    .resharing_key
                    .proposed_parameters()
                    .participants()
                    .id(a.id())
                    .unwrap()
            })
            .unwrap();

        check_call_success(
            leader
                .call(contract.id(), "start_reshare_instance")
                .args_json(json!({
                    "key_event_id": key_event_id,
                }))
                .max_gas()
                .transact()
                .await?,
        );

        // Wait for threshold participants to vote for resharing (2 out of 3)
        // The transition should happen after 2 votes when threshold is reached
        for account in remaining_accounts {
            check_call_success_all_receipts(
                account
                    .call(contract.id(), "vote_reshared")
                    .args_json(json!({
                        "key_event_id": key_event_id,
                    }))
                    .max_gas()
                    .transact()
                    .await?,
            );
        }
    }
    Ok(())
}
