pub mod common;

use crate::common::gen_accounts;
use anyhow::Result;
use assert_matches::assert_matches;
use attestation::attestation::{Attestation, MockAttestation};
use common::{
    check_call_success, get_tee_accounts, init_env_ed25519, init_env_secp256k1,
    submit_participant_info,
};
use mpc_contract::{
    errors::InvalidState, primitives::test_utils::bogus_ed25519_near_public_key,
    state::ProtocolContractState, tee::tee_state::NodeUid,
};
use mpc_primitives::hash::MpcDockerImageHash;
use near_sdk::PublicKey;
use near_workspaces::{Account, Contract};
use std::collections::BTreeSet;
use test_utils::attestation::{image_digest, mock_dstack_attestation, p2p_tls_key};

/// Tests the basic TEE verification functionality when no TEE accounts are present.
/// Verifies that the contract returns true for TEE verification even without any TEE accounts submitted,
/// and ensures the participant count remains unchanged during verification.
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

    let allowed_mpc_image_digest = image_digest();

    // Initially, there should be no allowed hashes
    assert_eq!(get_allowed_hashes(&contract).await?.len(), 0);
    assert_matches!(get_latest_code_hash(&contract).await, Err(_));

    // First vote - should not be enough
    vote_for_hash(&accounts[0], &contract, &allowed_mpc_image_digest).await?;
    assert_eq!(get_allowed_hashes(&contract).await?.len(), 0);
    // Should get an error when no code hash is available yet
    assert_matches!(get_latest_code_hash(&contract).await, Err(_));

    // Second vote - should reach threshold
    vote_for_hash(&accounts[1], &contract, &allowed_mpc_image_digest).await?;
    let allowed_hashes = get_allowed_hashes(&contract).await?;
    assert_eq!(allowed_hashes, vec![allowed_mpc_image_digest.clone()]);
    // latest_code_hash should return the same hash as the one in allowed_code_hashes
    assert_eq!(
        get_latest_code_hash(&contract).await?,
        Some(allowed_mpc_image_digest.clone())
    );

    // Additional votes - should not change the allowed hashes
    const EXTRA_VOTES_TO_TEST_STABILITY: usize = 4;
    for _ in 0..EXTRA_VOTES_TO_TEST_STABILITY {
        vote_for_hash(&accounts[2], &contract, &allowed_mpc_image_digest).await?;
        // Should still have exactly one hash
        let allowed_hashes = get_allowed_hashes(&contract).await?;
        assert_eq!(allowed_hashes, vec![allowed_mpc_image_digest.clone()]);
        // latest_code_hash should still return the same hash
        assert_eq!(
            get_latest_code_hash(&contract).await?,
            Some(allowed_mpc_image_digest.clone())
        );
    }

    Ok(())
}

/// Tests that once a code hash reaches voting threshold and becomes allowed,
/// it remains in the allowed list even when participants change their votes away from it.
#[tokio::test]
async fn test_vote_code_hash_approved_hashes_persist_after_vote_changes() -> Result<()> {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;

    let first_hash = image_digest();

    let arbitrary_bytes = [2; 32];
    let second_hash = MpcDockerImageHash::from(arbitrary_bytes);

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
    let allowed_mpc_image_digest = image_digest();

    let res = random_account
        .call(contract.id(), "vote_code_hash")
        .args_json(serde_json::json!({"code_hash": allowed_mpc_image_digest}))
        .transact()
        .await?;
    let Err(err) = res.into_result() else {
        panic!("vote_code_hash should not accept votes from a randomly generated account id that is not in the participant list");
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

/// Sets up a contract with an approved MPC hash by having the first two participants vote for it.
/// This is a helper function commonly used in tests that require pre-approved hashes.
async fn setup_approved_mpc_hash(contract: &Contract, accounts: &[Account]) -> Result<()> {
    let mpc_hash = image_digest();
    vote_for_hash(&accounts[0], contract, &mpc_hash).await?;
    vote_for_hash(&accounts[1], contract, &mpc_hash).await?;
    Ok(())
}

/// Sets up a complete TEE test environment with contract, accounts, mock attestation, and TLS key.
/// This is a helper function that provides all the common components needed for TEE-related tests.
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
    let success = submit_participant_info(&accounts[0], &contract, &attestation, &tls_key).await?;
    assert!(!success);
    Ok(())
}

/// **Test method with matching measurements** - Tests that participant info submission succeeds with the test-only method.
/// Unlike the test above, this one has an approved MPC hash. It uses the test method with custom measurements that match
/// the attestation data.
#[tokio::test]
async fn test_submit_participant_info_test_method_available_in_integration_tests() -> Result<()> {
    let (contract, accounts, attestation, tls_key) = setup_tee_test().await?;
    setup_approved_mpc_hash(&contract, &accounts).await?;
    let success = submit_participant_info(&accounts[0], &contract, &attestation, &tls_key).await?;
    assert!(success);
    Ok(())
}

/// **Mock attestation bypass** - Tests that participant info submission succeeds with mock attestation.
/// Different from the dstack attestation tests above, this uses a mock attestation which bypasses complex TEE verification.
/// This demonstrates that the submission mechanism itself works when attestation verification passes.
#[tokio::test]
async fn test_submit_participant_info_succeeds_with_mock_attestation() -> Result<()> {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;
    let mock_attestation = Attestation::Mock(MockAttestation::Valid);
    let tls_key = p2p_tls_key();
    let success =
        submit_participant_info(&accounts[0], &contract, &mock_attestation, &tls_key).await?;
    assert!(success);
    Ok(())
}

/// **TLS key validation** - Tests that TEE attestation fails when TLS key doesn't match the one in report data.
/// Similar to the successful test method case above, but uses a deliberately corrupted TLS key to verify
/// that attestation validation properly checks the TLS key embedded in the attestation report.
#[tokio::test]
async fn test_tee_attestation_fails_with_invalid_tls_key() -> Result<()> {
    let (contract, accounts, attestation, tls_key) = setup_tee_test().await?;
    setup_approved_mpc_hash(&contract, &accounts).await?;

    // Create invalid TLS key by flipping the last bit
    let mut invalid_tls_key_bytes = tls_key.as_bytes().to_vec();
    let last_byte_idx = invalid_tls_key_bytes.len() - 1;
    invalid_tls_key_bytes[last_byte_idx] ^= 0x01;
    let invalid_tls_key = PublicKey::try_from(invalid_tls_key_bytes)?;

    let success =
        submit_participant_info(&accounts[0], &contract, &attestation, &invalid_tls_key).await?;
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
    assert!(!result.is_success());

    // Verify the error message indicates unauthorized access
    match result.into_result() {
        Err(failure) => {
            let error_msg = format!("{:?}", failure);
            assert!(error_msg.contains("Method clean_tee_status is private"));
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

    // extract initial participants:
    // Get current state to extract participant info
    let state: ProtocolContractState = contract.view("state").await?.json()?;
    let running_state = match state {
        ProtocolContractState::Running(running_state) => running_state,
        _ => panic!("Contract should be in running state initially"),
    };

    // Get current participants to construct proper ThresholdParameters
    let init_participants = running_state.parameters.participants().clone();

    let mut expected_participants = BTreeSet::new();
    for account in &accounts {
        let attestation = Attestation::Mock(MockAttestation::Valid); // todo #1109, add TLS key.
        let tls_key = init_participants
            .info(account.id())
            .unwrap()
            .sign_pk
            .clone();
        let success = submit_participant_info(account, &contract, &attestation, &tls_key).await?;
        expected_participants.insert(NodeUid {
            account_id: account.id().clone(),
            tls_public_key: tls_key,
        });
        assert!(success);
    }

    // Verify current participants have TEE data
    assert_eq!(get_tee_accounts(&contract).await?.len(), accounts.len());

    // Create additional accounts (non-participants) and submit TEE info for them
    const NUM_ADDITIONAL_ACCOUNTS: usize = 2;
    let additional_accounts = gen_accounts(&worker, NUM_ADDITIONAL_ACCOUNTS).await.0;
    for account in &additional_accounts {
        let tls_key = bogus_ed25519_near_public_key();
        let attestation = Attestation::Mock(MockAttestation::Valid); // todo #1109, add TLS key.
        let success = submit_participant_info(account, &contract, &attestation, &tls_key).await?;
        assert!(success);
    }

    // Verify we have TEE data for all accounts before cleanup
    let tee_participants_before = get_tee_accounts(&contract).await?;
    assert_eq!(
        tee_participants_before.len(),
        accounts.len() + additional_accounts.len()
    );

    // Contract should be able to call clean_tee_status on itself
    let result = contract
        .as_account()
        .call(contract.id(), "clean_tee_status")
        .args_json(serde_json::json!({}))
        .transact()
        .await?;

    assert!(result.is_success());

    // Verify cleanup worked: only current participants should have TEE data
    let tee_participants_after = get_tee_accounts(&contract).await?;
    assert_eq!(tee_participants_after.len(), accounts.len());

    let actual_participants: BTreeSet<_> = tee_participants_after.into_iter().collect();

    assert_eq!(expected_participants, actual_participants);

    Ok(())
}

#[tokio::test]
async fn new_hash_and_previous_hashes_under_grace_period_pass_attestation_verification(
) -> Result<()> {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;

    let hash_1 = MpcDockerImageHash::from([1; 32]);
    let hash_2 = MpcDockerImageHash::from([2; 32]);
    let hash_3 = MpcDockerImageHash::from([3; 32]);

    let participant_account_1 = &accounts[0];
    let participant_account_2 = &accounts[1];

    // Initially, there should be no allowed hashes
    assert_eq!(get_allowed_hashes(&contract).await?.len(), 0);
    assert_matches!(get_latest_code_hash(&contract).await, Err(_));

    let hashes = [hash_1, hash_2, hash_3];

    for (i, current_hash) in hashes.iter().enumerate() {
        vote_for_hash(participant_account_1, &contract, current_hash).await?;
        vote_for_hash(participant_account_2, &contract, current_hash).await?;

        let previous_and_current_approved_hashes = &hashes[..=i];

        for approved_hash in previous_and_current_approved_hashes {
            let mock_attestation = MockAttestation::WithConstraints {
                mpc_docker_image_hash: Some(approved_hash.clone()),
                launcher_docker_compose_hash: None,
                expiry_time_stamp_seconds: None,
            };
            let attestation = Attestation::Mock(mock_attestation);

            let dummy_tls_key = p2p_tls_key();

            let validation_success = submit_participant_info(
                participant_account_1,
                &contract,
                &attestation,
                &dummy_tls_key,
            )
            .await?;

            assert!(
                validation_success,
                "Attestation for all previous images must pass"
            );
        }
    }

    Ok(())
}
