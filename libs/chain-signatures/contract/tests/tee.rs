use anyhow::Result;
use assert_matches::assert_matches;
use common::{check_call_success, init_env_ed25519, init_env_secp256k1};
use mpc_contract::{errors::InvalidState, state::ProtocolContractState};
use mpc_primitives::hash::MpcDockerImageHash;
use near_workspaces::{Account, Contract};

use crate::common::gen_accounts;

pub mod common;

#[tokio::test]
async fn test_tee_verify_no_tee() -> Result<()> {
    let (_, contract, _, _) = init_env_ed25519(1).await;
    let n_participants_start = get_participants(&contract).await?;

    let verified_tee: bool = contract
        .call("verify_tee")
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await?
        .json()?;
    assert!(verified_tee);
    assert_eq!(n_participants_start, get_participants(&contract).await?);
    Ok(())
}

/// Tests the basic code hash voting mechanism including threshold behavior and vote stability.
/// Validates that votes below threshold don't allow hashes, reaching threshold allows them,
/// and additional votes don't change the allowed state or latest hash.
#[tokio::test]
async fn test_vote_code_hash_basic_threshold_and_stability() -> Result<()> {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;

    let mpc_hash = MpcDockerImageHash::from([
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56,
        0x78, 0x90,
    ]);

    // Initially, there should be no allowed hashes
    assert_eq!(get_allowed_hashes(&contract).await?.len(), 0);
    assert_matches!(get_latest_code_hash(&contract).await, Err(_));

    // First vote - should not be enough
    vote_for_hash(&accounts[0], &contract, &mpc_hash).await?;
    assert_eq!(get_allowed_hashes(&contract).await?.len(), 0);
    // Should get an error when no code hash is available yet
    assert_matches!(get_latest_code_hash(&contract).await, Err(_));

    // Second vote - should reach threshold
    vote_for_hash(&accounts[1], &contract, &mpc_hash).await?;
    let allowed_hashes = get_allowed_hashes(&contract).await?;
    assert_eq!(allowed_hashes, vec![mpc_hash.clone()]);
    // latest_code_hash should return the same hash as the one in allowed_code_hashes
    assert_eq!(
        get_latest_code_hash(&contract).await?,
        Some(mpc_hash.clone())
    );

    // Additional votes - should not change the allowed hashes
    const EXTRA_VOTES_TO_TEST_STABILITY: usize = 4;
    for _ in 0..EXTRA_VOTES_TO_TEST_STABILITY {
        vote_for_hash(&accounts[2], &contract, &mpc_hash).await?;
        // Should still have exactly one hash
        let allowed_hashes = get_allowed_hashes(&contract).await?;
        assert_eq!(allowed_hashes, vec![mpc_hash.clone()]);
        // latest_code_hash should still return the same hash
        assert_eq!(
            get_latest_code_hash(&contract).await?,
            Some(mpc_hash.clone())
        );
    }

    Ok(())
}

/// Tests that once a code hash reaches voting threshold and becomes allowed,
/// it remains in the allowed list even when participants change their votes away from it.
#[tokio::test]
async fn test_vote_code_hash_approved_hashes_persist_after_vote_changes() -> Result<()> {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;

    let first_hash = MpcDockerImageHash::from([
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56,
        0x78, 0x90,
    ]);
    let second_hash = MpcDockerImageHash::from([
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd,
        0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
        0xcd, 0xef,
    ]);

    // Initially, there should be no allowed hashes
    assert_eq!(get_allowed_hashes(&contract).await?.len(), 0);
    assert_matches!(get_latest_code_hash(&contract).await, Err(_));

    // Initial votes for first hash - reach threshold
    vote_for_hash(&accounts[0], &contract, &first_hash).await?;
    vote_for_hash(&accounts[1], &contract, &first_hash).await?;

    // Verify first hash is allowed
    let allowed_hashes = get_allowed_hashes(&contract).await?;
    assert_eq!(allowed_hashes, vec![first_hash.clone()]);
    assert_eq!(
        get_latest_code_hash(&contract).await?,
        Some(first_hash.clone())
    );

    // Participant 0 changes vote to second hash
    vote_for_hash(&accounts[0], &contract, &second_hash).await?;

    // First hash should still be allowed (participant 1 still votes for it)
    // Second hash should not be allowed yet (only 1 vote)
    let allowed_hashes = get_allowed_hashes(&contract).await?;
    assert_eq!(allowed_hashes, vec![first_hash.clone()]);
    assert_eq!(
        get_latest_code_hash(&contract).await?,
        Some(first_hash.clone())
    );

    // Participant 2 votes for second hash - should reach threshold
    vote_for_hash(&accounts[2], &contract, &second_hash).await?;

    // Now both hashes should be allowed
    let allowed_hashes = get_allowed_hashes(&contract).await?;
    assert_eq!(allowed_hashes.len(), 2);
    assert!(allowed_hashes.contains(&first_hash));
    assert!(allowed_hashes.contains(&second_hash));
    // Latest should be the second hash (most recently added)
    assert_eq!(
        get_latest_code_hash(&contract).await?,
        Some(second_hash.clone())
    );

    // Participant 1 also changes vote to second hash
    vote_for_hash(&accounts[1], &contract, &second_hash).await?;

    // Both hashes should still be allowed (once a hash reaches threshold, it stays)
    // Second hash should still be allowed (3 votes)
    let allowed_hashes = get_allowed_hashes(&contract).await?;
    assert_eq!(allowed_hashes.len(), 2);
    assert!(allowed_hashes.contains(&first_hash));
    assert!(allowed_hashes.contains(&second_hash));
    // Latest should still be the second hash
    assert_eq!(
        get_latest_code_hash(&contract).await?,
        Some(second_hash.clone())
    );

    Ok(())
}

/// Tests that vote_code_hash does not accept votes from a randomly generated
/// account id that is not in the participant list
#[tokio::test]
async fn test_vote_code_hash_doesnt_accept_account_id_not_in_participant_list() -> Result<()> {
    let (worker, contract, _accounts, _) = init_env_secp256k1(1).await;
    let random_account = &gen_accounts(&worker, 1).await.0[0];
    let hash = MpcDockerImageHash::from([
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56,
        0x78, 0x90,
    ]);
    let res = random_account
        .call(contract.id(), "vote_code_hash")
        .args_json(serde_json::json!({"code_hash": hash}))
        .transact()
        .await?;
    let Err(err) = res.into_result() else {
        panic!("expected failure");
    };
    let expected = format!("{:?}", InvalidState::NotParticipant);
    let err_str = format!("{:?}", err);
    assert!(err_str.contains(&expected));
    Ok(())
}

async fn get_allowed_hashes(contract: &Contract) -> Result<Vec<MpcDockerImageHash>> {
    Ok(contract
        .call("allowed_code_hashes")
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await?
        .json::<Vec<MpcDockerImageHash>>()?)
}

async fn get_latest_code_hash(contract: &Contract) -> Result<Option<MpcDockerImageHash>> {
    Ok(contract
        .call("latest_code_hash")
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await?
        .json::<Option<MpcDockerImageHash>>()?)
}

async fn vote_for_hash(
    account: &Account,
    contract: &Contract,
    hash: &MpcDockerImageHash,
) -> Result<()> {
    check_call_success(
        account
            .call(contract.id(), "vote_code_hash")
            .args_json(serde_json::json!({"code_hash": hash}))
            .transact()
            .await?,
    );
    Ok(())
}

async fn get_participants(contract: &Contract) -> Result<usize> {
    let state = contract
        .call("state")
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await?;
    let value: ProtocolContractState = state.json()?;
    let ProtocolContractState::Running(running) = value else {
        panic!("Expected running state")
    };
    Ok(running.parameters.participants().len())
}

// todo [#514](https://github.com/near/mpc/issues/514)
