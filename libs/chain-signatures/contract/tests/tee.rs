pub mod common;

use crate::common::gen_accounts;
use anyhow::Result;
use assert_matches::assert_matches;
use attestation::attestation::Attestation;
use common::{
    check_call_success, get_tee_accounts, init_env_ed25519, init_env_secp256k1,
    submit_participant_info, submit_participant_info_with_measurements,
};
use mpc_contract::{errors::InvalidState, state::ProtocolContractState};
use mpc_primitives::hash::MpcDockerImageHash;
use near_sdk::PublicKey;
use near_workspaces::{Account, Contract};
use std::collections::HashSet;
use test_utils::attestation::{
    mock_dstack_attestation, mock_local_attestation, p2p_tls_key, test_expected_measurements,
};
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
        panic!("vote_code_hash should not accept votes from a randomly generated account id that is not in the participant list");
    };
    let expected = format!("{:?}", InvalidState::NotParticipant);
    let err_str = format!("{:?}", err);
    assert!(
        err_str.contains(&expected),
        "expected failure due to voter not being a participant"
    );
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

/// Helper function to set up contract with approved MPC hash.
async fn setup_contract_with_approved_hash(
    contract: &Contract,
    accounts: &[Account],
) -> Result<()> {
    let mpc_hash = MpcDockerImageHash::from([
        0xc2, 0x29, 0x01, 0xe5, 0x2c, 0xfa, 0x91, 0xb2, 0xe7, 0x1e, 0xb8, 0x69, 0x4a, 0xc9, 0x55,
        0x80, 0x65, 0xc6, 0xe3, 0xb1, 0x37, 0x83, 0xd9, 0xe3, 0xd3, 0x6b, 0x79, 0x2d, 0x93, 0xce,
        0x15, 0x3b,
    ]);
    vote_for_hash(&accounts[0], contract, &mpc_hash).await?;
    vote_for_hash(&accounts[1], contract, &mpc_hash).await?;
    Ok(())
}

/// Helper function to set up test environment with attestation and TLS key.
async fn setup_tee_test() -> Result<(Contract, Vec<Account>, Attestation, PublicKey)> {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;
    let attestation = mock_dstack_attestation();
    let tls_key = p2p_tls_key();
    Ok((contract, accounts, attestation, tls_key))
}

/// **No MPC hash approval** - Tests that participant info submission fails when no MPC hash has been approved yet.
/// This verifies the prerequisite step: the contract requires MPC hash approval before accepting any participant TEE information.
#[tokio::test]
async fn test_submit_participant_info_fails_without_approved_mpc_hash() -> Result<()> {
    let (contract, accounts, attestation, tls_key) = setup_tee_test().await?;
    let success = submit_participant_info_with_measurements(
        &accounts[0],
        &contract,
        &attestation,
        &tls_key,
        &test_expected_measurements(),
    )
    .await?;
    assert!(!success);
    Ok(())
}

/// **Test method with matching measurements** - Tests that participant info submission succeeds with the test-only method.
/// Unlike the test above, this one has an approved MPC hash. It uses the test method with custom measurements that match
/// the attestation data.
#[tokio::test]
async fn test_submit_participant_info_test_method_available_in_integration_tests() -> Result<()> {
    let (contract, accounts, attestation, tls_key) = setup_tee_test().await?;
    setup_contract_with_approved_hash(&contract, &accounts).await?;
    let success = submit_participant_info_with_measurements(
        &accounts[0],
        &contract,
        &attestation,
        &tls_key,
        &test_expected_measurements(),
    )
    .await?;
    assert!(success);
    Ok(())
}

/// **Production method with mismatched measurements** - Tests that the production method rejects test attestation data.
/// Similar setup to the test above (approved hash + valid attestation), but uses the production method [`submit_participant_info`]
/// which has hardcoded production measurements that don't match the test attestation data.
#[tokio::test]
async fn test_submit_participant_info_rejects_invalid_measurements() -> Result<()> {
    let (contract, accounts, attestation, tls_key) = setup_tee_test().await?;
    setup_contract_with_approved_hash(&contract, &accounts).await?;
    let success = submit_participant_info(&accounts[0], &contract, &attestation, &tls_key).await?;
    assert!(!success);
    Ok(())
}

/// **Local attestation bypass** - Tests that participant info submission succeeds with local attestation.
/// Different from the dstack attestation tests above, this uses local attestation which bypasses complex TEE verification.
/// This demonstrates that the submission mechanism itself works when attestation verification passes.
#[tokio::test]
async fn test_submit_participant_info_succeeds_with_local_attestation() -> Result<()> {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;
    let local_attestation = mock_local_attestation(true);
    let tls_key = p2p_tls_key();
    let success =
        submit_participant_info(&accounts[0], &contract, &local_attestation, &tls_key).await?;
    assert!(success);
    Ok(())
}

/// **TLS key validation** - Tests that TEE attestation fails when TLS key doesn't match the one in report data.
/// Similar to the successful test method case above, but uses a deliberately corrupted TLS key to verify
/// that attestation validation properly checks the TLS key embedded in the attestation report.
#[tokio::test]
async fn test_tee_attestation_fails_with_invalid_tls_key() -> Result<()> {
    let (contract, accounts, attestation, tls_key) = setup_tee_test().await?;
    setup_contract_with_approved_hash(&contract, &accounts).await?;

    // Create invalid TLS key by flipping the last bit
    let mut invalid_tls_key_bytes = tls_key.as_bytes().to_vec();
    let last_byte_idx = invalid_tls_key_bytes.len() - 1;
    invalid_tls_key_bytes[last_byte_idx] ^= 0x01;
    let invalid_tls_key = PublicKey::try_from(invalid_tls_key_bytes)?;

    let success = submit_participant_info_with_measurements(
        &accounts[0],
        &contract,
        &attestation,
        &invalid_tls_key,
        &test_expected_measurements(),
    )
    .await?;
    assert!(!success);
    Ok(())
}

/// **Access control validation** - Tests that external accounts cannot call the private clean_tee_status contract method.
/// This verifies the security boundary: only the contract itself should be able to perform internal cleanup operations.
#[tokio::test]
async fn test_clean_tee_status_denies_external_account_access() -> Result<()> {
    let (worker, contract, _accounts, _) = init_env_secp256k1(1).await;

    // Create a new account that's not the contract
    let external_account = worker.dev_create_account().await?;

    // Try to call clean_tee_status from external account - should fail
    let result = external_account
        .call(contract.id(), "clean_tee_status")
        .args_json(serde_json::json!({}))
        .transact()
        .await?;

    // The call should fail because it's not from the contract itself
    assert!(
        !result.is_success(),
        "External account should not be able to call clean_tee_status"
    );

    // Verify the error message indicates unauthorized access
    match result.into_result() {
        Err(failure) => {
            let error_msg = format!("{:?}", failure);
            assert!(
                error_msg.contains("Method clean_tee_status is private"),
                "Error should indicate private method access: {}",
                error_msg
            );
        }
        Ok(_) => panic!("Call should have failed"),
    }

    Ok(())
}

/// **TEE cleanup functionality** - Tests that the clean_tee_status contract method works correctly when called by the contract itself.
/// Unlike the access control test above, this demonstrates the positive case: the contract can successfully clean up
/// TEE data for accounts that are no longer participants. Uses the test method to populate initial TEE state.
#[tokio::test]
async fn test_clean_tee_status_succeeds_when_contract_calls_itself() -> Result<()> {
    let (worker, contract, accounts, _) = init_env_secp256k1(1).await;

    // Initially should have no TEE participants
    assert_eq!(get_tee_accounts(&contract).await?.len(), 0);

    // Setup contract with approved hash and submit TEE info for current participants
    setup_contract_with_approved_hash(&contract, &accounts).await?;
    let tls_key = p2p_tls_key();
    let attestation = mock_dstack_attestation();
    let test_measurements = test_expected_measurements();

    for account in &accounts {
        let success = submit_participant_info_with_measurements(
            account,
            &contract,
            &attestation,
            &tls_key,
            &test_measurements,
        )
        .await?;
        assert!(
            success,
            "Failed to submit participant info for account: {}",
            account.id()
        );
    }

    // Verify current participants have TEE data
    assert_eq!(get_tee_accounts(&contract).await?.len(), accounts.len());

    // Create additional accounts (non-participants) and submit TEE info for them
    const NUM_ADDITIONAL_ACCOUNTS: usize = 2;
    let additional_accounts = gen_accounts(&worker, NUM_ADDITIONAL_ACCOUNTS).await.0;
    for account in &additional_accounts {
        let success = submit_participant_info_with_measurements(
            account,
            &contract,
            &attestation,
            &tls_key,
            &test_measurements,
        )
        .await?;
        assert!(
            success,
            "Failed to submit participant info for additional account: {}",
            account.id()
        );
    }

    // Verify we have TEE data for all accounts before cleanup
    let tee_participants_before = get_tee_accounts(&contract).await?;
    assert_eq!(
        tee_participants_before.len(),
        accounts.len() + additional_accounts.len(),
        "Should have TEE data for all participants and additional accounts before cleanup"
    );

    // Contract should be able to call clean_tee_status on itself
    let result = contract
        .as_account()
        .call(contract.id(), "clean_tee_status")
        .args_json(serde_json::json!({}))
        .transact()
        .await?;

    assert!(
        result.is_success(),
        "Contract should be able to call clean_tee_status on itself"
    );

    // Verify cleanup worked: only current participants should have TEE data
    let tee_participants_after = get_tee_accounts(&contract).await?;
    assert_eq!(
        tee_participants_after.len(),
        accounts.len(),
        "Should only have TEE data for current participants after cleanup"
    );

    let expected_participants: HashSet<_> = accounts
        .iter()
        .map(|account| account.id().clone())
        .collect();
    let actual_participants: HashSet<_> = tee_participants_after.into_iter().collect();

    assert_eq!(
        expected_participants, actual_participants,
        "Remaining TEE participants should exactly match the current parameter set"
    );

    Ok(())
}
