use crate::sandbox::common::{
    assert_running_return_threshold, gen_accounts, init_env, submit_participant_info,
    IntoInterfaceType, GAS_FOR_VOTE_RESHARED, PARTICIPANT_LEN,
};
use assert_matches::assert_matches;
use contract_interface::types as dtos;
use mpc_contract::{
    errors::InvalidParameters,
    primitives::{
        domain::SignatureScheme,
        thresholds::{Threshold, ThresholdParameters},
    },
    state::{running::RunningContractState, ProtocolContractState},
};
use near_workspaces::{network::Sandbox, Account, Contract, Worker};
use rstest::rstest;
use serde_json::json;

#[tokio::test]
async fn test_keygen() -> anyhow::Result<()> {
    // TODO: this test does not cannot scale yet
    let (_, contract, accounts, _) = init_env(&[SignatureScheme::Secp256k1], 3).await;
    let args = json!({
        "domains": vec![
            json!({
                "id": 2,
                "scheme": "Ed25519",
            })
        ]
    });
    for account in accounts.iter() {
        let result = account
            .call(contract.id(), "vote_add_domains")
            .args_json(args.clone())
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();
    match state {
        ProtocolContractState::Initializing(state) => {
            assert_eq!(state.domains.domains().len(), 2);
        }
        _ => panic!("should be in initializing state"),
    };

    let result = accounts[0]
        .call(contract.id(), "start_keygen_instance")
        .args_json(json!({
            "key_event_id": {
                "epoch_id": 5,
                "domain_id": 2,
                "attempt_id": 0,
            },
        }))
        .transact()
        .await?;
    assert!(result.is_success(), "{result:#?}");

    let pk: dtos::PublicKey = "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae"
        .parse()
        .unwrap();
    let vote_pk_args = json!( {
        "key_event_id": {
            "epoch_id": 5,
            "domain_id": 2,
            "attempt_id": 0,
        },
        "public_key": pk,
    });

    for account in accounts.iter() {
        println!("{:?}", account);
        let result = account
            .call(contract.id(), "vote_pk")
            .args_json(vote_pk_args.clone())
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }
    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();
    match state {
        ProtocolContractState::Running(state) => {
            assert_eq!(state.keyset.epoch_id.get(), 5); // we started with 5, should not change.
            assert_eq!(state.domains.domains().len(), 2);
        }
        _ => panic!("should be in running state"),
    };

    Ok(())
}

#[tokio::test]
async fn test_cancel_keygen() -> anyhow::Result<()> {
    let (_, contract, accounts, _) = init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    let threshold = assert_running_return_threshold(&contract).await?;
    let args = json!({
        "domains": vec![
            json!({
                "id": 2,
                "scheme": "Ed25519",
            })
        ]
    });
    for account in accounts.iter() {
        let result = account
            .call(contract.id(), "vote_add_domains")
            .args_json(args.clone())
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();
    match state {
        ProtocolContractState::Initializing(state) => {
            assert_eq!(state.domains.domains().len(), 2);
        }
        _ => panic!("should be in initializing state"),
    };

    for account in accounts.iter().take(threshold.value() as usize) {
        let result = account
            .call(contract.id(), "vote_cancel_keygen")
            .args_json(json!({
                "next_domain_id": 3,
            }))
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();
    match state {
        ProtocolContractState::Running(state) => {
            assert_eq!(state.keyset.epoch_id.get(), 5); // we started with 5, should not change.
            assert_eq!(state.domains.domains().len(), 1);
        }
        _ => panic!("should be in running state"),
    };

    Ok(())
}

#[tokio::test]
async fn test_resharing() -> anyhow::Result<()> {
    // TODO: this test does not cannot scale yet
    let (worker, contract, mut accounts, _) = init_env(&[SignatureScheme::Secp256k1], 3).await;

    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    let existing_params = match state {
        ProtocolContractState::Running(state) => state.parameters,
        _ => panic!("should be in running state"),
    };
    let threshold = existing_params.threshold();
    let mut new_participants = existing_params.participants().clone();
    let (acc, p) = gen_accounts(&worker, 1).await;
    let new_p = p.participants().first().unwrap().clone();

    let new_account = &acc[0];

    // Submit attestation for the new participant, otherwise
    // the contract will reject the resharing.
    submit_participant_info(
        new_account,
        &contract,
        &dtos::Attestation::Mock(dtos::MockAttestation::Valid),
        &new_p.2.sign_pk.into_interface_type(),
    )
    .await
    .expect("Attestation submission for new account must succeed.");

    new_participants.insert(new_p.0.clone(), new_p.2).unwrap();
    let total_participants = new_participants.len();
    accounts.push(acc[0].clone());
    let proposal =
        ThresholdParameters::new(new_participants, Threshold::new(threshold.value() + 1)).unwrap();

    for account in &accounts {
        let result = account
            .call(contract.id(), "vote_new_parameters")
            .args_json(json!({
                "prospective_epoch_id": 6,
                "proposal": proposal,
            }))
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    match state {
        ProtocolContractState::Resharing(resharing_contract_state) => {
            assert_eq!(
                resharing_contract_state.resharing_key.proposed_parameters(),
                &proposal
            );
        }
        _ => panic!("should be in resharing state"),
    }

    let result = accounts[0]
        .call(contract.id(), "start_reshare_instance")
        .args_json(json!({
            "key_event_id": {
                "epoch_id": 6,
                "domain_id": 0,
                "attempt_id": 0,
            },
        }))
        .transact()
        .await?;
    assert!(result.is_success(), "{result:#?}");

    let vote_reshared_args = json!( {
        "key_event_id": {
            "epoch_id": 6,
            "domain_id": 0,
            "attempt_id": 0,
        },
    });

    for account in &accounts {
        let result = account
            .call(contract.id(), "vote_reshared")
            .gas(GAS_FOR_VOTE_RESHARED)
            .args_json(vote_reshared_args.clone())
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    match state {
        ProtocolContractState::Running(state) => {
            assert_eq!(state.parameters.participants().len(), total_participants);
            assert_eq!(state.keyset.epoch_id.get(), 6); // we started with 5.
        }
        _ => panic!("should be in running state"),
    };

    Ok(())
}

#[tokio::test]
async fn test_repropose_resharing() -> anyhow::Result<()> {
    // TODO: this test does not cannot scale yet
    let (worker, contract, mut accounts, _) = init_env(&[SignatureScheme::Secp256k1], 3).await;

    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    let existing_params = match state {
        ProtocolContractState::Running(state) => state.parameters,
        _ => panic!("should be in running state"),
    };
    let threshold = existing_params.threshold();
    let mut new_participants = existing_params.participants().clone();
    let (acc, p) = gen_accounts(&worker, 1).await;
    let new_p = p.participants().first().unwrap().clone();

    let new_account = &acc[0];

    // Submit attestation for the new participant, otherwise
    // the contract will reject the resharing.
    submit_participant_info(
        new_account,
        &contract,
        &dtos::Attestation::Mock(dtos::MockAttestation::Valid),
        &new_p.2.sign_pk.into_interface_type(),
    )
    .await
    .expect("Attestation submission for new account must succeed.");

    new_participants.insert(new_p.0.clone(), new_p.2).unwrap();
    let proposal =
        ThresholdParameters::new(new_participants, Threshold::new(threshold.value() + 1)).unwrap();
    accounts.push(new_account.clone());
    for account in &accounts {
        let result = account
            .call(contract.id(), "vote_new_parameters")
            .args_json(json!({
                "prospective_epoch_id": 6,
                "proposal": proposal,
            }))
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    match state {
        ProtocolContractState::Resharing(state) => {
            assert_eq!(state.resharing_key.proposed_parameters(), &proposal);
        }
        _ => panic!("should be in resharing state"),
    }

    for account in accounts.iter().take(accounts.len() - 1) {
        let result = account
            .call(contract.id(), "vote_new_parameters")
            .args_json(json!({
                "prospective_epoch_id": 7,
                "proposal": existing_params,
            }))
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    match state {
        ProtocolContractState::Resharing(state) => {
            assert_eq!(
                state
                    .resharing_key
                    .proposed_parameters()
                    .participants()
                    .len(),
                accounts.len() - 1
            );
            assert_eq!(state.resharing_key.epoch_id().get(), 7); // we started with 5.
        }
        _ => panic!("should be in resharing state"),
    };
    Ok(())
}

struct ResharingTestContext {
    _worker: Worker<Sandbox>,
    contract: Contract,
    current_participant_accounts: Vec<Account>,
    new_participant_account: Account,
    threshold_parameters: ThresholdParameters,
    initial_running_state: RunningContractState,
}

/// Test helper: Initialize environment and transition to resharing state
#[rstest::fixture]
async fn setup_resharing_state() -> ResharingTestContext {
    // TODO: tests depending on this function do not scale yet
    let (worker, contract, mut current_participant_accounts, _) =
        init_env(&[SignatureScheme::Secp256k1], 3).await;

    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();
    let ProtocolContractState::Running(initial_running_state) = state else {
        panic!("State is not running: {:#?}", state)
    };

    let initial_epoch_id = initial_running_state.keyset.epoch_id;
    let existing_params = initial_running_state.parameters.clone();
    let mut new_participants = existing_params.participants().clone();

    // Add a new participant
    let (new_account, new_account_id, new_participant_info) = {
        let (mut new_accounts, participants) = gen_accounts(&worker, 1).await;
        let (new_account_id, _, new_participant_info) =
            participants.participants().first().unwrap().clone();
        let new_account = new_accounts.pop().unwrap();
        (new_account, new_account_id, new_participant_info)
    };

    // Submit attestation for the new participant, otherwise
    // the contract will reject the resharing.
    submit_participant_info(
        &new_account,
        &contract,
        &dtos::Attestation::Mock(dtos::MockAttestation::Valid),
        &new_participant_info.sign_pk.into_interface_type(),
    )
    .await
    .expect("Attestation submission for new account must succeed.");

    new_participants
        .insert(new_account_id.clone(), new_participant_info)
        .unwrap();
    let threshold_parameters =
        ThresholdParameters::new(new_participants, Threshold::new(3)).unwrap();

    current_participant_accounts.push(new_account.clone());

    // Vote to transition to resharing state
    for account in &current_participant_accounts {
        let result = account
            .call(contract.id(), "vote_new_parameters")
            .args_json(json!({
                "prospective_epoch_id": initial_epoch_id.next(),
                "proposal": threshold_parameters,
            }))
            .transact()
            .await
            .unwrap();
        assert!(result.is_success(), "{result:#?}");
    }

    // Verify we're in resharing state
    match contract.view("state").await.unwrap().json().unwrap() {
        ProtocolContractState::Resharing(state) => {
            assert_eq!(
                state.resharing_key.proposed_parameters(),
                &threshold_parameters
            );
            assert_eq!(state.resharing_key.epoch_id(), initial_epoch_id.next());
        }
        _ => panic!("should be in resharing state"),
    }

    ResharingTestContext {
        _worker: worker,
        contract,
        current_participant_accounts,
        new_participant_account: new_account,
        threshold_parameters,
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
        current_participant_accounts,
        new_participant_account,
        initial_running_state,
        ..
    } = setup_resharing_state.await;

    let initial_threshold = initial_running_state.parameters.threshold();
    assert_ne!(
        initial_threshold.value(),
        1,
        "Sanity check failed. Initial_threshold should be at least 2 or greater for the purpose of this test."
    );

    // Filter out the new participant to get only previous participants
    let previous_participants: Vec<_> = current_participant_accounts
        .iter()
        .filter(|account| account.id() != new_participant_account.id())
        .collect();

    // Try to submit threshold votes with just one account (should not work due to idempotency)
    let account_1 = previous_participants[0];
    for _ in 0..initial_threshold.value() {
        let result = account_1
            .call(contract.id(), "vote_cancel_resharing")
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    // Verify still in resharing state - multiple votes from same account don't count
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    assert!(
        matches!(state, ProtocolContractState::Resharing(_)),
        "Contract should still be in resharing state. A threshold number of unique votes have not been cast."
    );

    // Now vote with remaining accounts to reach threshold
    // account_1 already voted once, so we need (threshold - 1) more unique votes
    let remaining_votes_needed = (initial_threshold.value() - 1) as usize;

    for account in previous_participants
        .iter()
        .filter(|account| account.id() != account_1.id()) // Skip account_1 which already voted
        .take(remaining_votes_needed)
    {
        let result = account
            .call(contract.id(), "vote_cancel_resharing")
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    // Check that state transitions back to running
    let new_state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    assert_matches!(
        new_state,
        ProtocolContractState::Running(_),
        "State must transition back to running after voting for cancellation"
    );

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
        current_participant_accounts,
        new_participant_account,
        initial_running_state,
        ..
    } = setup_resharing_state.await;

    let initial_threshold = initial_running_state.parameters.threshold();

    // Filter out the new participant account
    let previous_participants: Vec<_> = current_participant_accounts
        .iter()
        .filter(|account| account.id() != new_participant_account.id())
        .collect();

    // Vote with less than threshold (threshold - 1)
    for account in previous_participants
        .iter()
        .take((initial_threshold.value() - 1) as usize)
    {
        let result = account
            .call(contract.id(), "vote_cancel_resharing")
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    // Verify still in resharing state (not cancelled yet)
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    assert!(
        matches!(state, ProtocolContractState::Resharing(_)),
        "Should still be in resharing state with insufficient votes"
    );

    // Add one more vote to reach threshold
    let result = previous_participants[initial_threshold.value() as usize - 1]
        .call(contract.id(), "vote_cancel_resharing")
        .transact()
        .await?;
    assert!(result.is_success(), "{result:#?}");

    // Verify transition back to running state
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
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
        new_participant_account,
        ..
    } = setup_resharing_state.await;

    assert!(
        new_participant_account
            .call(contract.id(), "vote_cancel_resharing")
            .transact()
            .await?
            .is_failure(),
        "A new participant should not be able to vote for cancellation"
    );

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
        current_participant_accounts,
        new_participant_account,
        initial_running_state,
        ..
    } = setup_resharing_state.await;

    let initial_threshold = initial_running_state.parameters.threshold();
    let initial_epoch_id = initial_running_state.keyset.epoch_id;

    // Vote for cancellation with threshold of previous running participants
    for account in current_participant_accounts
        .iter()
        .filter(|account| account.id() != new_participant_account.id())
        .take(initial_threshold.value() as usize)
    {
        let result = account
            .call(contract.id(), "vote_cancel_resharing")
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    // Check that state transitions back to running
    let new_state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    let ProtocolContractState::Running(mut new_running_state) = new_state else {
        panic!(
            "State must transition back to running after voting for cancellation {:#?}",
            new_state
        )
    };

    let cancelled_epoch_id = initial_epoch_id.next();

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
        current_participant_accounts,
        new_participant_account,
        threshold_parameters,
        initial_running_state,
        ..
    } = setup_resharing_state.await;

    let initial_threshold = initial_running_state.parameters.threshold();
    let initial_epoch_id = initial_running_state.keyset.epoch_id;

    // Cancel the resharing
    for account in current_participant_accounts
        .iter()
        .filter(|account| account.id() != new_participant_account.id())
        .take(initial_threshold.value() as usize)
    {
        let result = account
            .call(contract.id(), "vote_cancel_resharing")
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    let cancelled_epoch_id = initial_epoch_id.next();
    let prospective_epoch_id = cancelled_epoch_id.next();

    // Verify state tracks cancelled epoch
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    if let ProtocolContractState::Running(running_state) = state {
        assert_eq!(
            running_state.previously_cancelled_resharing_epoch_id,
            Some(cancelled_epoch_id)
        );
    }

    // Check that starting a new resharing with cancelled epoch id fails
    for account in &current_participant_accounts {
        assert!(
            account
                .call(contract.id(), "vote_new_parameters")
                .args_json(json!({
                    "prospective_epoch_id": cancelled_epoch_id.get(),
                    "proposal": threshold_parameters,
                }))
                .transact()
                .await?
                .is_failure(),
            "Voting for resharing with cancelled epoch id should be rejected"
        );
    }

    // Verify we can initiate resharing with the next epoch ID
    for account in &current_participant_accounts {
        let result = account
            .call(contract.id(), "vote_new_parameters")
            .args_json(json!({
                "prospective_epoch_id": prospective_epoch_id.get(),
                "proposal": threshold_parameters,
            }))
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    // Verify successful transition to resharing with correct epoch
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    match state {
        ProtocolContractState::Resharing(resharing_contract_state) => {
            assert_eq!(
                resharing_contract_state.resharing_key.proposed_parameters(),
                &threshold_parameters
            );
            assert_eq!(
                resharing_contract_state.prospective_epoch_id(),
                prospective_epoch_id,
                "Should skip cancelled epoch and use next available epoch ID"
            );
        }
        _ => panic!("should be in resharing state"),
    }

    Ok(())
}

/// Test: After cancellation and successful resharing, `previously_cancelled_resharing_epoch_id`
/// in the running state is set to None.
#[rstest]
#[tokio::test]
async fn test_successful_resharing_after_cancellation_clears_cancelled_epoch_id(
    #[future] setup_resharing_state: ResharingTestContext,
) -> anyhow::Result<()> {
    let ResharingTestContext {
        contract,
        current_participant_accounts,
        new_participant_account,
        threshold_parameters,
        initial_running_state,
        ..
    } = setup_resharing_state.await;

    let initial_threshold = initial_running_state.parameters.threshold();
    let initial_epoch_id = initial_running_state.keyset.epoch_id;

    // Step 1: Cancel the resharing
    for account in current_participant_accounts
        .iter()
        .filter(|account| account.id() != new_participant_account.id())
        .take(initial_threshold.value() as usize)
    {
        let result = account
            .call(contract.id(), "vote_cancel_resharing")
            .gas(GAS_FOR_VOTE_RESHARED)
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    let cancelled_epoch_id = initial_epoch_id.next();
    let prospective_epoch_id = cancelled_epoch_id.next();

    // Verify cancellation tracked
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    if let ProtocolContractState::Running(running_state) = state {
        assert_eq!(
            running_state.previously_cancelled_resharing_epoch_id,
            Some(cancelled_epoch_id),
            "Should track cancelled epoch after cancellation"
        );
    }

    // Step 2: Initiate new resharing with next epoch ID
    for account in &current_participant_accounts {
        let result = account
            .call(contract.id(), "vote_new_parameters")
            .args_json(json!({
                "prospective_epoch_id": prospective_epoch_id.get(),
                "proposal": threshold_parameters,
            }))
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    // Verify in resharing state
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    match state {
        ProtocolContractState::Resharing(resharing_state) => {
            assert_eq!(
                resharing_state.resharing_key.epoch_id(),
                prospective_epoch_id
            );
        }
        _ => panic!("should be in resharing state"),
    }

    // Step 3: Start reshare instance
    let result = current_participant_accounts[0]
        .call(contract.id(), "start_reshare_instance")
        .args_json(json!({
            "key_event_id": {
                "epoch_id": prospective_epoch_id.get(),
                "domain_id": 0,
                "attempt_id": 0,
            },
        }))
        .transact()
        .await?;
    assert!(result.is_success(), "{result:#?}");

    // Step 4: Vote reshared
    let vote_reshared_args = json!({
        "key_event_id": {
            "epoch_id": prospective_epoch_id.get(),
            "domain_id": 0,
            "attempt_id": 0,
        },
    });

    for account in &current_participant_accounts {
        let result = account
            .call(contract.id(), "vote_reshared")
            .gas(GAS_FOR_VOTE_RESHARED)
            .args_json(vote_reshared_args.clone())
            .transact()
            .await?;
        assert!(result.is_success(), "{result:#?}");
    }

    // Step 5: Verify final state
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
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
                running_state.parameters.participants().len(),
                current_participant_accounts.len(),
                "Should have updated participant count"
            );
        }
        _ => panic!("should be in running state after successful resharing"),
    }

    Ok(())
}

#[tokio::test]
async fn vote_new_parameters_errors_if_new_participant_is_missing_valid_attestation() {
    let (worker, contract, mut current_participant_accounts, _) =
        init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_LEN).await;
    let threshold = assert_running_return_threshold(&contract).await.unwrap();

    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();
    let ProtocolContractState::Running(initial_running_state) = state else {
        panic!("State is not running: {:#?}", state)
    };

    let initial_epoch_id = initial_running_state.keyset.epoch_id;
    let existing_params = initial_running_state.parameters.clone();
    let mut participants = existing_params.participants().clone();

    // Add a new participant
    let (new_account, new_account_id, new_participant_info) = {
        let (mut new_accounts, participants) = gen_accounts(&worker, 1).await;
        let (new_account_id, _, new_participant_info) =
            participants.participants().first().unwrap().clone();
        let new_account = new_accounts.pop().unwrap();
        (new_account, new_account_id, new_participant_info)
    };

    // Add the new participant to the participant set, and propose this to the contract.
    participants
        .insert(new_account_id.clone(), new_participant_info)
        .unwrap();

    let threshold_parameters =
        ThresholdParameters::new(participants, Threshold::new(threshold.value() + 1)).unwrap();

    current_participant_accounts.push(new_account.clone());

    // Vote to transition to resharing state
    for account in &current_participant_accounts {
        let call_result = account
            .call(contract.id(), "vote_new_parameters")
            .max_gas()
            .args_json(json!({
                "prospective_epoch_id": initial_epoch_id.next(),
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

    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();

    assert_matches!(
        state,
        ProtocolContractState::Running(_),
        "Protocol state should not transition when new participant has invalid TEE status."
    );
}
