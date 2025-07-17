pub mod common;

use common::{check_call_success, gen_accounts, init_env_secp256k1};
use mpc_contract::{
    primitives::{
        key_state::EpochId,
        thresholds::{Threshold, ThresholdParameters},
    },
    state::ProtocolContractState,
};
use near_sdk::PublicKey;
use serde_json::json;
use std::str::FromStr;

#[tokio::test]
async fn test_keygen() -> anyhow::Result<()> {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;

    let args = json!({
        "domains": vec![
            json!({
                "id": 2,
                "scheme": "Ed25519",
            })
        ]
    });
    for i in [0, 1, 2] {
        check_call_success(
            accounts[i]
                .call(contract.id(), "vote_add_domains")
                .args_json(args.clone())
                .transact()
                .await?,
        );
    }

    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();
    match state {
        ProtocolContractState::Initializing(state) => {
            assert_eq!(state.domains.domains().len(), 2);
        }
        _ => panic!("should be in initializing state"),
    };

    check_call_success(
        accounts[0]
            .call(contract.id(), "start_keygen_instance")
            .args_json(json!({
                "key_event_id": {
                    "epoch_id": 5,
                    "domain_id": 2,
                    "attempt_id": 0,
                },
            }))
            .transact()
            .await?,
    );

    let pk = PublicKey::from_str("ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae").unwrap();
    let vote_pk_args = json!( {
        "key_event_id": {
            "epoch_id": 5,
            "domain_id": 2,
            "attempt_id": 0,
        },
        "public_key": pk,
    });

    for account in &accounts[0..3] {
        check_call_success(
            account
                .call(contract.id(), "vote_pk")
                .args_json(vote_pk_args.clone())
                .transact()
                .await?,
        );
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
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;

    let args = json!({
        "domains": vec![
            json!({
                "id": 2,
                "scheme": "Ed25519",
            })
        ]
    });
    for i in [0, 1, 2] {
        check_call_success(
            accounts[i]
                .call(contract.id(), "vote_add_domains")
                .args_json(args.clone())
                .transact()
                .await?,
        );
    }

    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();
    match state {
        ProtocolContractState::Initializing(state) => {
            assert_eq!(state.domains.domains().len(), 2);
        }
        _ => panic!("should be in initializing state"),
    };

    for i in [0, 2] {
        check_call_success(
            accounts[i]
                .call(contract.id(), "vote_cancel_keygen")
                .args_json(json!({
                    "next_domain_id": 3,
                }))
                .transact()
                .await?,
        );
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
    let (worker, contract, mut accounts, _) = init_env_secp256k1(1).await;

    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    let existing_params = match state {
        ProtocolContractState::Running(state) => state.parameters,
        _ => panic!("should be in running state"),
    };
    let mut new_participants = existing_params.participants().clone();
    let (acc, p) = gen_accounts(&worker, 1).await;
    let new_p = p.participants().first().unwrap().clone();
    new_participants.insert(new_p.0.clone(), new_p.2).unwrap();
    accounts.push(acc[0].clone());
    let proposal = ThresholdParameters::new(new_participants, Threshold::new(3)).unwrap();

    for account in &accounts {
        check_call_success(
            account
                .call(contract.id(), "vote_new_parameters")
                .args_json(json!({
                    "prospective_epoch_id": 6,
                    "proposal": proposal,
                }))
                .transact()
                .await?,
        );
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

    check_call_success(
        accounts[0]
            .call(contract.id(), "start_reshare_instance")
            .args_json(json!({
                "key_event_id": {
                    "epoch_id": 6,
                    "domain_id": 0,
                    "attempt_id": 0,
                },
            }))
            .transact()
            .await?,
    );

    let vote_reshared_args = json!( {
        "key_event_id": {
            "epoch_id": 6,
            "domain_id": 0,
            "attempt_id": 0,
        },
    });

    for account in &accounts {
        check_call_success(
            account
                .call(contract.id(), "vote_reshared")
                .args_json(vote_reshared_args.clone())
                .transact()
                .await?,
        );
    }

    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    match state {
        ProtocolContractState::Running(state) => {
            assert_eq!(state.parameters.participants().len(), 4);
            assert_eq!(state.keyset.epoch_id.get(), 6); // we started with 5.
        }
        _ => panic!("should be in running state"),
    };

    Ok(())
}

#[tokio::test]
async fn test_repropose_resharing() -> anyhow::Result<()> {
    let (worker, contract, mut accounts, _) = init_env_secp256k1(1).await;

    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    let existing_params = match state {
        ProtocolContractState::Running(state) => state.parameters,
        _ => panic!("should be in running state"),
    };
    let mut new_participants = existing_params.participants().clone();
    let (acc, p) = gen_accounts(&worker, 1).await;
    let new_p = p.participants().first().unwrap().clone();
    new_participants.insert(new_p.0.clone(), new_p.2).unwrap();
    let proposal = ThresholdParameters::new(new_participants, Threshold::new(3)).unwrap();
    accounts.push(acc[0].clone());
    for account in &accounts {
        check_call_success(
            account
                .call(contract.id(), "vote_new_parameters")
                .args_json(json!({
                    "prospective_epoch_id": 6,
                    "proposal": proposal,
                }))
                .transact()
                .await?,
        );
    }
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    match state {
        ProtocolContractState::Resharing(state) => {
            assert_eq!(state.resharing_key.proposed_parameters(), &proposal);
        }
        _ => panic!("should be in resharing state"),
    }

    for i in [0, 1, 2] {
        check_call_success(
            accounts[i]
                .call(contract.id(), "vote_new_parameters")
                .args_json(json!({
                    "prospective_epoch_id": 7,
                    "proposal": existing_params,
                }))
                .transact()
                .await?,
        );
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
                3
            );
            assert_eq!(state.resharing_key.epoch_id().get(), 7); // we started with 5.
        }
        _ => panic!("should be in resharing state"),
    };
    Ok(())
}

/// Test scenario: Verifies the cancellation mechanism of key resharing.
///
/// Test scenario:
/// 1. Initial State. Contract starts in Running state with epoch 5.
/// 2. Initiate Resharing: All participants vote for new parameters transitioning the contract to Resharing state.
/// 3. Cancel Resharing.
/// 4. Prevent Epoch Reuse. Attempt to initiate resharing with the cancelled epoch 6
///    is rejected by the contract.
/// 5. Resume Resharing. Successfully initiate a new resharing with the next epoch ID (7),
///    demonstrating that the contract correctly tracks and skips cancelled epochs.
///
/// Invariants tested:
/// - Cancellation requires threshold votes from previous running state.
/// - Double votes are rejected.
/// - Only votes from participants in the previous running state are considered.
/// - The contract state reverts to the running state upon cancellation of a resharing.
/// - Cancelled epoch IDs cannot be reused for future resharing attempts.
#[tokio::test]
async fn test_cancel_resharing() -> anyhow::Result<()> {
    const INITIAL_EPOCH_ID: EpochId = EpochId::new(5);

    let (worker, contract, mut accounts, _) = init_env_secp256k1(1).await;

    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    let ProtocolContractState::Running(state) = state else {
        panic!("State is not running: {:#?}", state)
    };

    let initial_threshold = state.parameters.threshold();
    let initial_running_state = state.clone();

    assert_eq!(
        initial_running_state.cancelled_resharing_epoch_id, None,
        "There have been no resharing state yet for the cancellation epoch id to be maintained."
    );

    assert_eq!(
        initial_running_state.keyset.epoch_id, INITIAL_EPOCH_ID,
        "Current epoch ID has wrong initial value."
    );

    let existing_params = state.parameters;

    let mut new_participants = existing_params.participants().clone();

    let (new_account, new_account_id, new_participant_info) = {
        let (mut new_accounts, participants) = gen_accounts(&worker, 1).await;
        let (new_account_id, _, new_participant_info) =
            participants.participants().first().unwrap().clone();
        let new_account = new_accounts.pop().unwrap();

        (new_account, new_account_id, new_participant_info)
    };

    new_participants
        .insert(new_account_id.clone(), new_participant_info)
        .unwrap();
    let proposal = ThresholdParameters::new(new_participants, Threshold::new(3)).unwrap();

    accounts.push(new_account.clone());
    for account in &accounts {
        check_call_success(
            account
                .call(contract.id(), "vote_new_parameters")
                .args_json(json!({
                    "prospective_epoch_id": INITIAL_EPOCH_ID.next(),
                    "proposal": proposal,
                }))
                .transact()
                .await?,
        );
    }
    match contract.view("state").await.unwrap().json()? {
        ProtocolContractState::Resharing(state) => {
            assert_eq!(state.resharing_key.proposed_parameters(), &proposal);
            assert_eq!(state.resharing_key.epoch_id(), INITIAL_EPOCH_ID.next());
        }
        _ => panic!("should be in resharing state"),
    }

    // New participant can not vote for cancellation.
    assert!(
        new_account
            .call(contract.id(), "vote_cancel_resharing")
            .transact()
            .await?
            .is_failure(),
        "A new participant can not vote for cancellation"
    );

    // Vote for cancellation with previous running participants
    for account in accounts
        .iter()
        .filter(|account| *account.id() != new_account_id)
        .take(initial_threshold.value() as usize)
    {
        let account_votes_for_cancellation = async || {
            account
                .call(contract.id(), "vote_cancel_resharing")
                .transact()
                .await
        };
        check_call_success(account_votes_for_cancellation().await?);
        assert!(
            account_votes_for_cancellation().await?.is_failure(),
            "Voting again with same account should fail as re-votes are not allowed."
        )
    }

    // Check that state transitions back to running
    let new_state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    let ProtocolContractState::Running(mut new_running_state) = new_state else {
        panic!(
            "State must transition back to running after voting for cancellation {:#?}",
            new_state
        )
    };

    const CANCELLED_EPOCH_ID: EpochId = EpochId::new(6);
    const PROSPECTIVE_EPOCH_ID: EpochId = CANCELLED_EPOCH_ID.next();

    assert_eq!(
        new_running_state.cancelled_resharing_epoch_id,
        Some(CANCELLED_EPOCH_ID),
        "Unexpected prospective epoch id after cancellation."
    );
    assert_eq!(
        new_running_state.keyset.epoch_id, INITIAL_EPOCH_ID,
        "Current epoch ID should remain unchanged after a cancellation."
    );

    // Set this field to none for equality check.
    // (The previous running set was not the result of a cancellation, thus has `cancelled_resharing_epoch_id`
    // set to None)
    new_running_state.cancelled_resharing_epoch_id = None;
    assert_eq!(new_running_state, initial_running_state);

    // Check that starting a new resharing with epoch id that was cancelled fails
    for account in &accounts {
        assert!(
            account
                .call(contract.id(), "vote_new_parameters")
                .args_json(json!({
                    "prospective_epoch_id": CANCELLED_EPOCH_ID.get(),
                    "proposal": proposal,
                }))
                .transact()
                .await?
                .is_failure(),
            "Voting for re-sharing with epoch id that got cancelled should be rejected by the contract."
        );
    }

    // Perform resharing.
    for account in &accounts {
        check_call_success(
            account
                .call(contract.id(), "vote_new_parameters")
                .args_json(json!({
                    "prospective_epoch_id": PROSPECTIVE_EPOCH_ID.get(),
                    "proposal": proposal,
                }))
                .transact()
                .await?,
        );
    }
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    match state {
        ProtocolContractState::Resharing(resharing_contract_state) => {
            assert_eq!(
                resharing_contract_state.resharing_key.proposed_parameters(),
                &proposal
            );

            assert_eq!(
                resharing_contract_state.prospective_epoch_id(),
                PROSPECTIVE_EPOCH_ID,
                "Re-entering resharing did not account for the previously cancelled resharing when selecting epoch ID."
            )
        }
        _ => panic!("should be in resharing state"),
    }

    Ok(())
}
