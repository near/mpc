// TODO(#1657): split this file
use crate::sandbox::{
    common::{
        gen_account, gen_participant_info, generate_participant_and_submit_attestation, init_env,
        SandboxTestSetup,
    },
    utils::{
        consts::{ALL_SIGNATURE_SCHEMES, GAS_FOR_VOTE_CANCEL_KEYGEN, PARTICIPANT_LEN},
        initializing_utils::{start_keygen_instance, vote_add_domains, vote_public_key},
        interface::{IntoContractType, IntoInterfaceType},
        mpc_contract::get_state,
        resharing_utils::{conclude_resharing, vote_cancel_reshaing, vote_new_parameters},
        transactions::execute_async_transactions,
    },
};
use assert_matches::assert_matches;
use contract_interface::types as dtos;
use dtos::{ProtocolContractState, RunningContractState};
use mpc_contract::{
    errors::InvalidParameters,
    primitives::{
        domain::{DomainConfig, SignatureScheme},
        key_state::{AttemptId, KeyEventId},
        thresholds::{Threshold, ThresholdParameters},
    },
};
use near_workspaces::{network::Sandbox, Account, Contract, Worker};
use rstest::rstest;
use serde_json::json;

#[tokio::test]
async fn test_keygen() -> anyhow::Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;
    let init_state = get_state(&contract).await;
    let ProtocolContractState::Running(ref init_running) = init_state else {
        panic!("expected running state");
    };
    let epoch_id = init_running.keyset.epoch_id;
    let domain_id = init_running.domains.next_domain_id;
    let scheme = SignatureScheme::Ed25519;

    // vote to add the domain and verify we enter initializing state
    vote_add_domains(
        &contract,
        &mpc_signer_accounts,
        &[DomainConfig {
            id: domain_id.into(),
            scheme,
        }],
    )
    .await
    .unwrap();
    let state = get_state(&contract).await;
    let ProtocolContractState::Initializing(ref init) = state else {
        panic!("expected initializing state");
    };
    assert_eq!(init.domains.next_domain_id, domain_id + 1);
    let found = init
        .domains
        .domains
        .iter()
        .find(|d| d.id.0 == domain_id)
        .unwrap();
    assert_eq!(scheme.into_interface_type(), found.scheme);
    assert_eq!(domain_id, found.id.0);

    // start the keygen instance and vote for a new public key
    let key_event_id = KeyEventId {
        epoch_id: mpc_contract::primitives::key_state::EpochId::new(epoch_id.0),
        domain_id: domain_id.into(),
        attempt_id: AttemptId::new(),
    };
    start_keygen_instance(&contract, &mpc_signer_accounts, key_event_id)
        .await
        .unwrap();
    let public_key: dtos::PublicKey = "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae"
        .parse()
        .unwrap();
    vote_public_key(
        &contract,
        &mpc_signer_accounts,
        key_event_id,
        public_key.clone(),
    )
    .await
    .unwrap();

    // ensure the protocol resumed running state and the public key was added
    let state = get_state(&contract).await;
    let ProtocolContractState::Running(ref running) = state else {
        panic!("expected running state");
    };
    let found_key: near_sdk::PublicKey = running
        .keyset
        .domains
        .iter()
        .find(|k| k.domain_id.0 == domain_id)
        .map(|k| &k.key)
        .unwrap()
        .into_contract_type();
    assert_eq!(found_key, public_key.into_contract_type());
    assert_eq!(
        running.domains.domains.len(),
        ALL_SIGNATURE_SCHEMES.len() + 1
    );
    // assert that the epoch id did not change
    assert_eq!(running.keyset.epoch_id, epoch_id);

    Ok(())
}

#[tokio::test]
async fn test_cancel_keygen() -> anyhow::Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;
    let init_state = get_state(&contract).await;
    let ProtocolContractState::Running(ref init_running) = init_state else {
        panic!("expected running state");
    };
    let epoch_id: u64 = init_running.keyset.epoch_id.0;
    let mut next_domain_id: u64 = init_running.domains.next_domain_id;
    for scheme in ALL_SIGNATURE_SCHEMES {
        let threshold = init_running.parameters.threshold.0 as usize;

        // vote to start key generation
        vote_add_domains(
            &contract,
            &mpc_signer_accounts,
            &[DomainConfig {
                id: next_domain_id.into(),
                scheme: *scheme,
            }],
        )
        .await
        .unwrap();

        let state = get_state(&contract).await;
        let ProtocolContractState::Initializing(ref init) = state else {
            panic!("expected initializing state");
        };
        assert_eq!(init.domains.next_domain_id, next_domain_id + 1);
        let found = init
            .domains
            .domains
            .iter()
            .find(|d| d.id.0 == next_domain_id)
            .unwrap();
        assert_eq!(next_domain_id, found.id.0);
        assert_eq!((*scheme).into_interface_type(), found.scheme);

        // send threshold votes to abort key generation
        execute_async_transactions(
            &mpc_signer_accounts[0..threshold],
            &contract,
            "vote_cancel_keygen",
            &json!({"next_domain_id": next_domain_id+1}),
            GAS_FOR_VOTE_CANCEL_KEYGEN,
        )
        .await
        .unwrap();

        // ensure we return to running state and that no key was registered
        let state = get_state(&contract).await;
        let ProtocolContractState::Running(ref running) = state else {
            panic!("expected running state");
        };
        assert!(
            running
                .keyset
                .domains
                .iter()
                .all(|k| k.domain_id.0 != next_domain_id),
            "No key should be registered for the cancelled domain"
        );
        assert_eq!(running.domains.domains.len(), ALL_SIGNATURE_SCHEMES.len());

        // assert that the epoch id did not change
        assert_eq!(running.keyset.epoch_id.0, epoch_id);
        assert_eq!(running.domains.next_domain_id, next_domain_id + 1);
        next_domain_id += 1;
    }
    Ok(())
}

#[tokio::test]
async fn test_resharing() -> anyhow::Result<()> {
    let ResharingTestContext {
        contract,
        persistent_participants,
        initial_running_state,
        new_participant_accounts,
        ..
    } = setup_resharing_state(PARTICIPANT_LEN).await;

    let mut all_accounts = persistent_participants.clone();
    all_accounts.extend_from_slice(&new_participant_accounts);
    let prospective_epoch_id = dtos::EpochId(
        initial_running_state
            .previously_cancelled_resharing_epoch_id
            .unwrap_or(initial_running_state.keyset.epoch_id)
            .0
            + 1,
    );
    conclude_resharing(
        &contract,
        &all_accounts,
        mpc_contract::primitives::key_state::EpochId::new(prospective_epoch_id.0),
    )
    .await
    .unwrap();

    let state: ProtocolContractState = get_state(&contract).await;
    match state {
        ProtocolContractState::Running(state) => {
            assert_eq!(
                state.parameters.participants.participants.len(),
                PARTICIPANT_LEN + 1
            );
            assert_eq!(state.keyset.epoch_id, prospective_epoch_id);
        }
        _ => panic!("should be in running state"),
    };

    Ok(())
}

#[tokio::test]
async fn test_repropose_resharing() -> anyhow::Result<()> {
    let ResharingTestContext {
        contract,
        persistent_participants,
        initial_running_state,
        ..
    } = setup_resharing_state(PARTICIPANT_LEN).await;

    let prospective_epoch_id = dtos::EpochId(
        initial_running_state
            .previously_cancelled_resharing_epoch_id
            .unwrap_or(initial_running_state.keyset.epoch_id)
            .0
            + 1,
    );
    let prospective_epoch_id = dtos::EpochId(prospective_epoch_id.0 + 1);
    let proposal = initial_running_state.parameters.clone();
    vote_new_parameters(
        &contract,
        prospective_epoch_id.0,
        &proposal,
        &persistent_participants,
        &[],
    )
    .await
    .unwrap();

    let state: ProtocolContractState = get_state(&contract).await;
    match state {
        ProtocolContractState::Resharing(state) => {
            assert_eq!(state.resharing_key.parameters, proposal);
            assert_eq!(state.resharing_key.epoch_id, prospective_epoch_id);
        }
        _ => panic!("should be in resharing state"),
    };
    Ok(())
}

struct ResharingTestContext {
    _worker: Worker<Sandbox>,
    contract: Contract,
    persistent_participants: Vec<Account>,
    new_participant_accounts: Vec<Account>,
    threshold_parameters: ThresholdParameters,
    initial_running_state: RunningContractState,
}

/// Test helper: Initialize environment and transition to resharing state
#[rstest::fixture]
async fn setup_resharing_state(
    #[default(PARTICIPANT_LEN)] number_of_participants: usize,
) -> ResharingTestContext {
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, number_of_participants).await;

    let state: ProtocolContractState = get_state(&contract).await;
    let ProtocolContractState::Running(initial_running_state) = state else {
        panic!("State is not running: {:#?}", state)
    };

    let threshold = initial_running_state.parameters.threshold;
    let mut new_participants: mpc_contract::primitives::participants::Participants =
        (&initial_running_state.parameters.participants).into_contract_type();

    // Add a new participant
    let (new_account, new_account_id, new_participant_info) =
        generate_participant_and_submit_attestation(&worker, &contract).await;
    let new_accounts = vec![new_account];

    new_participants
        .insert(new_account_id.clone(), new_participant_info)
        .unwrap();
    let proposal =
        ThresholdParameters::new(new_participants, Threshold::new(threshold.0 + 1)).unwrap();

    let prospective_epoch_id = dtos::EpochId(
        initial_running_state
            .previously_cancelled_resharing_epoch_id
            .unwrap_or(initial_running_state.keyset.epoch_id)
            .0
            + 1,
    );
    vote_new_parameters(
        &contract,
        prospective_epoch_id.0,
        &proposal,
        &mpc_signer_accounts,
        &new_accounts,
    )
    .await
    .unwrap();

    // Verify we're in resharing state
    match get_state(&contract).await {
        ProtocolContractState::Resharing(state) => {
            // Compare proposal parameters via JSON roundtrip (internal vs DTO types)
            let proposal_json = serde_json::to_value(&proposal).unwrap();
            let state_params_json = serde_json::to_value(&state.resharing_key.parameters).unwrap();
            assert_eq!(state_params_json, proposal_json);
            assert_eq!(state.resharing_key.epoch_id, prospective_epoch_id);
        }
        _ => panic!("should be in resharing state"),
    }

    ResharingTestContext {
        _worker: worker,
        contract,
        persistent_participants: mpc_signer_accounts,
        new_participant_accounts: new_accounts,
        threshold_parameters: proposal,
        initial_running_state,
    }
}

/// Test: vote_cancel_resharing is idempotent - multiple votes from same account count as one
#[rstest]
#[tokio::test]
async fn test_cancel_resharing_vote_is_idempotent(
    #[future] setup_resharing_state: ResharingTestContext,
) -> anyhow::Result<()> {
    let ResharingTestContext {
        contract,
        persistent_participants,
        initial_running_state,
        ..
    } = setup_resharing_state.await;

    let initial_threshold = initial_running_state.parameters.threshold.0 as usize;
    assert_ne!(
        initial_threshold,
        1,
        "Sanity check failed. Initial_threshold should be at least 2 or greater for the purpose of this test."
    );

    // Try to submit threshold votes with just one account (should not work due to idempotency)
    let account_1 = &persistent_participants[0];
    for _ in 0..initial_threshold {
        let result = account_1
            .call(contract.id(), "vote_cancel_resharing")
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    // Verify still in resharing state - multiple votes from same account don't count
    let state = get_state(&contract).await;
    assert!(
        matches!(state, ProtocolContractState::Resharing(_)),
        "Contract should still be in resharing state. A threshold number of unique votes have not been cast."
    );

    // Now vote with remaining accounts to reach threshold
    // account_1 already voted once, so we need (threshold - 1) more unique votes
    vote_cancel_reshaing(&contract, &persistent_participants[1..initial_threshold])
        .await
        .unwrap();

    // Check that state transitions back to running
    let new_state: ProtocolContractState = get_state(&contract).await;
    let ProtocolContractState::Running(mut found) = new_state else {
        panic!("expected running state");
    };

    assert_eq!(
        found.previously_cancelled_resharing_epoch_id,
        Some(dtos::EpochId(
            initial_running_state
                .previously_cancelled_resharing_epoch_id
                .unwrap_or(initial_running_state.keyset.epoch_id)
                .0
                + 1
        ))
    );

    found.previously_cancelled_resharing_epoch_id = None;
    assert_eq!(found, initial_running_state);
    Ok(())
}

/// Test: Cancellation requires threshold votes from previous running state
#[rstest]
#[tokio::test]
async fn test_cancel_resharing_requires_threshold_votes(
    #[future] setup_resharing_state: ResharingTestContext,
) -> anyhow::Result<()> {
    let ResharingTestContext {
        contract,
        persistent_participants,
        initial_running_state,
        ..
    } = setup_resharing_state.await;

    let initial_threshold = initial_running_state.parameters.threshold.0 as usize;

    // Vote with less than threshold (threshold - 1)
    vote_cancel_reshaing(
        &contract,
        &persistent_participants[0..initial_threshold - 1],
    )
    .await
    .unwrap();

    // Verify still in resharing state (not cancelled yet)
    let state: ProtocolContractState = get_state(&contract).await;
    assert!(
        matches!(state, ProtocolContractState::Resharing(_)),
        "Should still be in resharing state with insufficient votes"
    );

    // Add one more vote to reach threshold
    let result = persistent_participants[initial_threshold - 1]
        .call(contract.id(), "vote_cancel_resharing")
        .transact()
        .await?;
    assert!(result.is_success(), "{result:#?}");

    // Verify transition back to running state
    let state: ProtocolContractState = get_state(&contract).await;
    assert!(
        matches!(state, ProtocolContractState::Running(_)),
        "Should transition to running state after threshold votes"
    );

    Ok(())
}

/// Test: Only votes from participants in the previous running state are considered
#[rstest]
#[tokio::test]
async fn test_cancel_resharing_only_previous_participants_can_vote(
    #[future] setup_resharing_state: ResharingTestContext,
) -> anyhow::Result<()> {
    let ResharingTestContext {
        contract,
        new_participant_accounts,
        ..
    } = setup_resharing_state.await;

    for new_participant_account in new_participant_accounts {
        assert!(
            new_participant_account
                .call(contract.id(), "vote_cancel_resharing")
                .transact()
                .await?
                .is_failure(),
            "A new participant should not be able to vote for cancellation"
        );
    }

    Ok(())
}

/// Test: The contract state reverts to the previous
/// running state upon cancellation of a resharing.
#[rstest]
#[tokio::test]
async fn test_cancel_resharing_reverts_to_previous_running_state(
    #[future] setup_resharing_state: ResharingTestContext,
) -> anyhow::Result<()> {
    let ResharingTestContext {
        contract,
        persistent_participants,
        initial_running_state,
        ..
    } = setup_resharing_state.await;

    let initial_threshold = initial_running_state.parameters.threshold.0 as usize;

    // Vote for cancellation with threshold of previous running participants
    vote_cancel_reshaing(&contract, &persistent_participants[0..initial_threshold])
        .await
        .unwrap();
    // Check that state transitions back to running
    let new_state = get_state(&contract).await;

    let ProtocolContractState::Running(mut new_running_state) = new_state else {
        panic!(
            "State must transition back to running after voting for cancellation {:#?}",
            new_state
        )
    };

    let initial_epoch_id = initial_running_state.keyset.epoch_id;
    let cancelled_epoch_id = dtos::EpochId(initial_epoch_id.0 + 1);
    assert_eq!(
        new_running_state.previously_cancelled_resharing_epoch_id,
        Some(cancelled_epoch_id),
        "Should track the cancelled epoch id"
    );
    assert_eq!(
        new_running_state.keyset.epoch_id, initial_epoch_id,
        "Current epoch ID should remain unchanged after a cancellation"
    );

    // Set this field to none for equality check
    new_running_state.previously_cancelled_resharing_epoch_id = None;
    assert_eq!(
        new_running_state, initial_running_state,
        "State should revert to previous running state (except for cancelled epoch tracking)"
    );

    Ok(())
}

/// Test: Cancelled epoch IDs cannot be reused for future resharing attempts
#[rstest]
#[tokio::test]
async fn test_cancelled_epoch_cannot_be_reused(
    #[future] setup_resharing_state: ResharingTestContext,
) -> anyhow::Result<()> {
    let ResharingTestContext {
        contract,
        persistent_participants,
        new_participant_accounts,
        threshold_parameters,
        initial_running_state,
        ..
    } = setup_resharing_state.await;

    let initial_threshold = initial_running_state.parameters.threshold;
    let initial_epoch_id = initial_running_state.keyset.epoch_id;

    // Cancel the resharing
    vote_cancel_reshaing(
        &contract,
        &persistent_participants[0..initial_threshold.0 as usize],
    )
    .await
    .unwrap();

    let cancelled_epoch_id = dtos::EpochId(initial_epoch_id.0 + 1);
    let prospective_epoch_id = dtos::EpochId(cancelled_epoch_id.0 + 1);

    // Verify state tracks cancelled epoch
    let state = get_state(&contract).await;
    if let ProtocolContractState::Running(running_state) = state {
        assert_eq!(
            running_state.previously_cancelled_resharing_epoch_id,
            Some(cancelled_epoch_id)
        );
    }

    // Check that starting a new resharing with cancelled epoch id fails
    for account in &persistent_participants {
        assert!(
            account
                .call(contract.id(), "vote_new_parameters")
                .args_json(json!({
                    "prospective_epoch_id": cancelled_epoch_id.0,
                    "proposal": threshold_parameters,
                }))
                .transact()
                .await?
                .is_failure(),
            "Voting for resharing with cancelled epoch id should be rejected"
        );
    }

    // Verify we can initiate resharing with the next epoch ID
    vote_new_parameters(
        &contract,
        prospective_epoch_id.0,
        &threshold_parameters,
        &persistent_participants,
        &new_participant_accounts,
    )
    .await
    .unwrap();

    // Verify successful transition to resharing with correct epoch
    let state = get_state(&contract).await;
    match state {
        ProtocolContractState::Resharing(resharing_contract_state) => {
            assert_eq!(
                serde_json::to_value(&resharing_contract_state.resharing_key.parameters).unwrap(),
                serde_json::to_value(&threshold_parameters).unwrap()
            );
            assert_eq!(
                resharing_contract_state.resharing_key.epoch_id, prospective_epoch_id,
                "Should skip cancelled epoch and use next available epoch ID"
            );
        }
        _ => panic!("should be in resharing state"),
    }

    Ok(())
}

/// Test: After cancellation and successful resharing, `previously_cancelled_resharing_epoch_id`
/// in the running state is set to None.
#[tokio::test]
async fn test_successful_resharing_after_cancellation_clears_cancelled_epoch_id(
) -> anyhow::Result<()> {
    let ResharingTestContext {
        contract,
        persistent_participants,
        new_participant_accounts,
        threshold_parameters,
        initial_running_state,
        ..
    } = setup_resharing_state(PARTICIPANT_LEN).await;

    let initial_threshold = initial_running_state.parameters.threshold;
    let initial_epoch_id = initial_running_state.keyset.epoch_id;

    // Step 1: Cancel the resharing
    vote_cancel_reshaing(
        &contract,
        &persistent_participants[0..initial_threshold.0 as usize],
    )
    .await
    .unwrap();

    let cancelled_epoch_id = dtos::EpochId(initial_epoch_id.0 + 1);
    let prospective_epoch_id = dtos::EpochId(cancelled_epoch_id.0 + 1);

    // Verify cancellation tracked
    let state: ProtocolContractState = get_state(&contract).await;
    if let ProtocolContractState::Running(running_state) = state {
        assert_eq!(
            running_state.previously_cancelled_resharing_epoch_id,
            Some(cancelled_epoch_id),
            "Should track cancelled epoch after cancellation"
        );
    }

    // Step 2: Initiate new resharing with next epoch ID
    vote_new_parameters(
        &contract,
        prospective_epoch_id.0,
        &threshold_parameters,
        &persistent_participants,
        &new_participant_accounts,
    )
    .await
    .unwrap();

    // Verify in resharing state
    let state: ProtocolContractState = get_state(&contract).await;
    match state {
        ProtocolContractState::Resharing(resharing_state) => {
            assert_eq!(resharing_state.resharing_key.epoch_id, prospective_epoch_id);
        }
        _ => panic!("should be in resharing state"),
    }

    // Step 3: Start reshare instance
    let mut all_participants = persistent_participants;
    all_participants.extend_from_slice(&new_participant_accounts);
    conclude_resharing(
        &contract,
        &all_participants,
        mpc_contract::primitives::key_state::EpochId::new(prospective_epoch_id.0),
    )
    .await
    .unwrap();

    // Step 5: Verify final state
    let state: ProtocolContractState = get_state(&contract).await;
    match state {
        ProtocolContractState::Running(running_state) => {
            assert_eq!(
                running_state.keyset.epoch_id, prospective_epoch_id,
                "Should be running with new epoch ID"
            );
            assert_eq!(
                running_state.previously_cancelled_resharing_epoch_id, None,
                "previously_cancelled_resharing_epoch_id should be None after successful resharing"
            );
            assert_eq!(
                serde_json::to_value(&running_state.parameters).unwrap(),
                serde_json::to_value(&threshold_parameters).unwrap(),
                "threshold parameters must match"
            );
        }
        _ => panic!("should be in running state after successful resharing"),
    }

    Ok(())
}

#[tokio::test]
async fn vote_new_parameters_errors_if_new_participant_is_missing_valid_attestation() {
    let SandboxTestSetup {
        worker,
        contract,
        mut mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;

    let state = get_state(&contract).await;
    let ProtocolContractState::Running(ref running_state) = state else {
        panic!("expected running state");
    };
    let threshold = running_state.parameters.threshold;
    let epoch_id = running_state.keyset.epoch_id;
    let mut proposed_participants: mpc_contract::primitives::participants::Participants =
        (&running_state.parameters.participants).into_contract_type();

    let (new_account, new_account_id) = gen_account(&worker).await;
    let new_participant_info = gen_participant_info();

    // Add the new participant to the participant set, and propose this to the contract.
    proposed_participants
        .insert(new_account_id.clone(), new_participant_info)
        .unwrap();

    let threshold_parameters =
        ThresholdParameters::new(proposed_participants, Threshold::new(threshold.0 + 1)).unwrap();

    mpc_signer_accounts.push(new_account.clone());

    // Vote to transition to resharing state
    for account in &mpc_signer_accounts {
        let call_result = account
            .call(contract.id(), "vote_new_parameters")
            .max_gas()
            .args_json(json!({
                "prospective_epoch_id": dtos::EpochId(epoch_id.0 + 1),
                "proposal": threshold_parameters,
            }))
            .transact()
            .await
            .unwrap()
            .into_result()
            .expect_err("calling `vote_new_parameters` must fail when one participant has invalid TEE status.");

        let error_message = call_result.to_string();
        let expected_error_message = InvalidParameters::InvalidTeeRemoteAttestation.to_string();
        assert!(error_message.contains(&expected_error_message));
    }

    let state: ProtocolContractState = get_state(&contract).await;

    assert_matches!(
        state,
        ProtocolContractState::Running(_),
        "Protocol state should not transition when new participant has invalid TEE status."
    );
}
