use crate::sandbox::{
    common::{gen_accounts, init_env, submit_tee_attestations, SandboxTestSetup},
    utils::{
        consts::{ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN},
        interface::{IntoContractType, IntoInterfaceType},
        mpc_contract::{
            assert_running_return_participants, assert_running_return_threshold,
            get_participant_attestation, get_state, get_tee_accounts, submit_participant_info,
            vote_for_hash,
        },
        resharing_utils::conclude_resharing,
    },
};
use anyhow::Result;
use contract_interface::types::{self as dtos, Attestation, MockAttestation};
use mpc_contract::{
    errors::InvalidState,
    primitives::{
        domain::SignatureScheme, participants::Participants, test_utils::bogus_ed25519_public_key,
    },
};
use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};
use near_workspaces::Contract;
use test_utils::attestation::{image_digest, p2p_tls_key};

/// Tests the basic code hash voting mechanism including threshold behavior and vote stability.
/// Validates that votes below threshold don't allow hashes, reaching threshold allows them,
/// and additional votes don't change the allowed state or latest hash.
#[tokio::test]
async fn test_vote_code_hash_basic_threshold_and_stability() -> Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;
    let threshold = assert_running_return_threshold(&contract).await;

    let allowed_mpc_image_digest = image_digest();

    // Initially, there should be no allowed hashes
    assert_eq!(get_allowed_hashes(&contract).await, vec![]);

    // First votes - should not be enough
    for account in mpc_signer_accounts.iter().take((threshold.0 - 1) as usize) {
        vote_for_hash(account, &contract, &allowed_mpc_image_digest).await?;
        assert_eq!(get_allowed_hashes(&contract).await, vec![]);
    }

    // `threshold`-th vote - should reach threshold
    vote_for_hash(
        &mpc_signer_accounts[(threshold.0 - 1) as usize],
        &contract,
        &allowed_mpc_image_digest,
    )
    .await?;
    let allowed_hashes = get_allowed_hashes(&contract).await;
    assert_eq!(allowed_hashes, vec![allowed_mpc_image_digest.clone()]);

    // Additional votes - should not change the allowed hashes
    const EXTRA_VOTES_TO_TEST_STABILITY: usize = 4;
    for _ in 0..EXTRA_VOTES_TO_TEST_STABILITY {
        vote_for_hash(
            &mpc_signer_accounts[2],
            &contract,
            &allowed_mpc_image_digest,
        )
        .await?;
        // Should still have exactly one hash
        let allowed_hashes = get_allowed_hashes(&contract).await;
        assert_eq!(allowed_hashes, vec![allowed_mpc_image_digest.clone()]);
    }

    Ok(())
}

/// Tests that once a code hash reaches voting threshold and becomes allowed,
/// it remains in the allowed list even when participants change their votes away from it.
#[tokio::test]
async fn test_vote_code_hash_approved_hashes_persist_after_vote_changes() -> Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;
    let threshold = assert_running_return_threshold(&contract).await;
    // This is necessary for some parts of the test below
    assert!((threshold.0 as usize) < mpc_signer_accounts.len());
    let first_hash = image_digest();

    let arbitrary_bytes = [2; 32];
    let second_hash = MpcDockerImageHash::from(arbitrary_bytes);

    // Initially, there should be no allowed hashes
    assert_eq!(get_allowed_hashes(&contract).await.len(), 0);
    assert_eq!(get_allowed_hashes(&contract).await, vec![]);

    // Initial votes for first hash - reach threshold
    for account in mpc_signer_accounts.iter().take(threshold.0 as usize) {
        vote_for_hash(account, &contract, &first_hash).await?;
    }

    // Verify first hash is allowed
    let allowed_hashes = get_allowed_hashes(&contract).await;
    assert_eq!(allowed_hashes, vec![first_hash.clone()]);

    // Participant 0 changes vote to second hash
    vote_for_hash(&mpc_signer_accounts[0], &contract, &second_hash).await?;

    // First hash should still be allowed
    // Second hash should not be allowed yet (only 1 vote)
    let allowed_hashes = get_allowed_hashes(&contract).await;
    assert_eq!(allowed_hashes, vec![first_hash.clone()]);

    // Participants 2..threshold votes for second hash - should reach threshold
    for account in mpc_signer_accounts
        .iter()
        .skip(2)
        .take(threshold.0 as usize - 1)
    {
        vote_for_hash(account, &contract, &second_hash).await?;
    }

    // Now both hashes should be allowed
    let allowed_hashes = get_allowed_hashes(&contract).await;
    assert_eq!(
        allowed_hashes,
        vec![second_hash.clone(), first_hash.clone()]
    );

    // Participant 1 also changes vote to second hash
    vote_for_hash(&mpc_signer_accounts[1], &contract, &second_hash).await?;

    // Both hashes should still be allowed (once a hash reaches threshold, it stays)
    // Second hash should still be allowed (threshold + 1 votes)
    let allowed_hashes = get_allowed_hashes(&contract).await;
    assert_eq!(
        allowed_hashes,
        vec![second_hash.clone(), first_hash.clone()]
    );

    Ok(())
}

/// Tests that vote_code_hash does not accept votes from a randomly generated
/// account id that is not in the participant list
#[tokio::test]
async fn test_vote_code_hash_doesnt_accept_account_id_not_in_participant_list() -> Result<()> {
    let SandboxTestSetup {
        worker, contract, ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;
    let random_account = &gen_accounts(&worker, 1).await.0[0];
    let allowed_mpc_image_digest = image_digest();

    let res = random_account
        .call(contract.id(), "vote_code_hash")
        .args_json(serde_json::json!({"code_hash": allowed_mpc_image_digest}))
        .transact()
        .await?;
    let Err(err) = res.into_result() else {
        panic!(
            "vote_code_hash should not accept votes from a randomly generated account id that is not in the participant list"
        );
    };
    let expected = format!("{:?}", InvalidState::NotParticipant);
    let err_str = format!("{:?}", err);
    assert!(err_str.contains(&expected));
    Ok(())
}

#[tokio::test]
async fn test_vote_code_hash_accepts_allowed_mpc_image_digest_hex_parameter() -> Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;
    let allowed_mpc_image_digest =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    let res = mpc_signer_accounts
        .first()
        .unwrap()
        .call(contract.id(), "vote_code_hash")
        .args_json(serde_json::json!({"code_hash": allowed_mpc_image_digest}))
        .transact()
        .await?;
    assert!(res.is_success());
    Ok(())
}

async fn get_allowed_launcher_compose_hashes(
    contract: &Contract,
) -> Result<Vec<LauncherDockerComposeHash>> {
    Ok(contract
        .call("allowed_launcher_compose_hashes")
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await?
        .json::<Vec<LauncherDockerComposeHash>>()?)
}

async fn get_allowed_hashes(contract: &Contract) -> Vec<MpcDockerImageHash> {
    contract
        .call("allowed_docker_image_hashes")
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await
        .expect("Contract is running")
        .json::<Vec<MpcDockerImageHash>>()
        .expect("allowed_docker_image_hashes method is infallible")
}

pub async fn get_participants(contract: &Contract) -> Result<usize> {
    let state = contract
        .call("state")
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await?;
    let value: dtos::ProtocolContractState = state.json()?;
    let dtos::ProtocolContractState::Running(running) = value else {
        panic!("Expected running state")
    };
    Ok(running.parameters.participants.participants.len())
}

// / **Mock attestation bypass** - Tests that participant info submission succeeds with mock attestation.
// / Different from the dstack attestation tests above, this uses a mock attestation which bypasses complex TEE verification.
/// This demonstrates that the submission mechanism itself works when attestation verification passes.
#[tokio::test]
async fn test_submit_participant_info_succeeds_with_mock_attestation() -> Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;
    let mock_attestation = Attestation::Mock(MockAttestation::Valid);
    let tls_key = p2p_tls_key().into();
    let success = submit_participant_info(
        &mpc_signer_accounts[0],
        &contract,
        &mock_attestation,
        &tls_key,
    )
    .await?
    .is_success();
    assert!(success);
    Ok(())
}

/// **Access control validation** - Tests that external accounts cannot call the private clean_tee_status contract method.
/// This verifies the security boundary: only the contract itself should be able to perform internal cleanup operations.
#[tokio::test]
async fn test_clean_tee_status_denies_external_account_access() -> Result<()> {
    let SandboxTestSetup {
        worker, contract, ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;

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
    let SandboxTestSetup {
        worker,
        contract,
        mut mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;

    let participant_uids = {
        let p: Participants =
            (&assert_running_return_participants(&contract).await?).into_contract_type();
        p.get_node_ids()
    };
    submit_tee_attestations(&contract, &mut mpc_signer_accounts, &participant_uids).await?;

    // Verify current participants have TEE data
    assert_eq!(get_tee_accounts(&contract).await?, participant_uids);

    // Create additional accounts (non-participants) and submit TEE info for them
    const NUM_ADDITIONAL_ACCOUNTS: usize = 2;
    let (mut additional_accounts, additional_participants) =
        gen_accounts(&worker, NUM_ADDITIONAL_ACCOUNTS).await;
    let additional_uids = additional_participants.get_node_ids();
    submit_tee_attestations(&contract, &mut additional_accounts, &additional_uids).await?;

    // Verify we have TEE data for all accounts before cleanup
    let tee_participants_before = get_tee_accounts(&contract).await?;
    assert_eq!(
        tee_participants_before,
        &additional_uids | &participant_uids
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
    assert_eq!(tee_participants_after.len(), mpc_signer_accounts.len());
    assert_eq!(participant_uids, tee_participants_after);

    Ok(())
}

#[tokio::test]
async fn new_hash_and_previous_hashes_under_grace_period_pass_attestation_verification(
) -> Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;
    let threshold = assert_running_return_threshold(&contract).await;
    let hash_1 = [1; 32];
    let hash_2 = [2; 32];
    let hash_3 = [3; 32];

    let participant_account_1 = &mpc_signer_accounts[0];

    // Initially, there should be no allowed hashes
    assert_eq!(get_allowed_hashes(&contract).await, vec![]);

    let hashes = [hash_1, hash_2, hash_3];

    for (i, current_hash) in hashes.iter().enumerate() {
        let hash = MpcDockerImageHash::from(*current_hash);
        for account in mpc_signer_accounts.iter().take(threshold.0 as usize) {
            vote_for_hash(account, &contract, &hash).await?;
        }

        let previous_and_current_approved_hashes = &hashes[..=i];

        for approved_hash in previous_and_current_approved_hashes {
            let mock_attestation = MockAttestation::WithConstraints {
                mpc_docker_image_hash: Some(*approved_hash),
                launcher_docker_compose_hash: None,
                expiry_timestamp_seconds: None,
            };
            let attestation = Attestation::Mock(mock_attestation);

            let dummy_tls_key = p2p_tls_key().into();

            let validation_success = submit_participant_info(
                participant_account_1,
                &contract,
                &attestation,
                &dummy_tls_key,
            )
            .await?
            .is_success();

            assert!(
                validation_success,
                "Attestation for all previous images must pass"
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn get_attestation_returns_none_when_tls_key_is_not_associated_with_an_attestation() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;

    let participant_account_1 = &mpc_signer_accounts[0];
    let tls_key_1 = bogus_ed25519_public_key();

    let tls_key_2 = bogus_ed25519_public_key();

    let validation_success = submit_participant_info(
        participant_account_1,
        &contract,
        &Attestation::Mock(MockAttestation::Valid),
        &tls_key_1,
    )
    .await
    .unwrap()
    .is_success();

    assert!(validation_success);

    let attestation_for_tls_key_2: Option<Attestation> =
        get_participant_attestation(&contract, &tls_key_2)
            .await
            .unwrap();

    assert_eq!(attestation_for_tls_key_2, None);
}

#[tokio::test]
async fn get_attestation_returns_some_when_tls_key_associated_with_an_attestation() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;

    let participant_account_1 = &mpc_signer_accounts[0];
    let tls_key_1 = bogus_ed25519_public_key();

    let tls_key_2 = bogus_ed25519_public_key();
    let participant_account_2 = &mpc_signer_accounts[1];

    assert_ne!(
        tls_key_1, tls_key_2,
        "Sanity check failed. Participant tls keys can not be equal for this test."
    );

    let participant_1_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(u64::MAX),
    });

    let participant_2_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(u64::MAX - 1),
    });

    assert_ne!(
        participant_1_attestation, participant_2_attestation,
        "Sanity check failed. Participants can not be equal for this test."
    );

    let validation_success = submit_participant_info(
        participant_account_1,
        &contract,
        &participant_1_attestation,
        &tls_key_1,
    )
    .await
    .unwrap()
    .is_success();
    assert!(validation_success, "Submitting attestation failed.");

    let validation_success = submit_participant_info(
        participant_account_2,
        &contract,
        &participant_2_attestation,
        &tls_key_2,
    )
    .await
    .unwrap()
    .is_success();
    assert!(validation_success, "Submitting attestation failed.");

    let attestation_for_tls_key_2: Option<Attestation> =
        get_participant_attestation(&contract, &tls_key_2)
            .await
            .unwrap();

    assert_eq!(attestation_for_tls_key_2, Some(participant_2_attestation));
}

#[tokio::test]
async fn get_attestation_overwrites_when_same_tls_key_is_reused() {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;

    let participant_account = &mpc_signer_accounts[0];
    let tls_key = bogus_ed25519_public_key();

    let first_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(u64::MAX),
    });

    let second_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(u64::MAX - 1),
    });

    assert_ne!(
        first_attestation, second_attestation,
        "Sanity check failed: attestations must differ for overwrite test"
    );

    // Submit the first attestation
    let validation_success =
        submit_participant_info(participant_account, &contract, &first_attestation, &tls_key)
            .await
            .unwrap()
            .is_success();
    assert!(validation_success, "First attestation submission failed");

    // Submit the second attestation with the same TLS key (overwrites the first)
    let validation_success = submit_participant_info(
        participant_account,
        &contract,
        &second_attestation,
        &tls_key,
    )
    .await
    .unwrap()
    .is_success();
    assert!(validation_success, "Second attestation submission failed");

    // Now the latest attestation should be returned
    let attestation_for_tls_key: Option<Attestation> =
        get_participant_attestation(&contract, &tls_key)
            .await
            .unwrap();

    assert_eq!(
        attestation_for_tls_key,
        Some(second_attestation),
        "Expected the second attestation to overwrite the first for the same TLS key"
    );
}

#[tokio::test]
async fn test_function_allowed_launcher_compose_hashes() -> anyhow::Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(ALL_SIGNATURE_SCHEMES, PARTICIPANT_LEN).await;

    let allowed_mpc_image_digest = image_digest();

    assert_eq!(
        get_allowed_launcher_compose_hashes(&contract).await?.len(),
        0
    );

    for account in mpc_signer_accounts {
        vote_for_hash(&account, &contract, &allowed_mpc_image_digest).await?;
    }

    assert_eq!(
        get_allowed_launcher_compose_hashes(&contract).await?.len(),
        1
    );

    Ok(())
}

/// Tests that when a participant's TEE attestation expires and `verify_tee()` is called,
/// the contract transitions to Resharing state and eventually removes that participant.
///
/// Steps:
/// 1. Initialize contract with 3 participants
/// 2. Submit an expiring attestation for the last participant
/// 3. Fast-forward blocks past the attestation expiry
/// 4. Call `verify_tee()` which detects the expired attestation and triggers resharing
/// 5. Complete resharing with remaining 2 participants
/// 6. Verify participant count reduced from 3 to 2
#[tokio::test]
async fn test_verify_tee_expired_attestation_triggers_resharing() -> Result<()> {
    const PARTICIPANT_COUNT: usize = 3;
    const ATTESTATION_EXPIRY_SECONDS: u64 = 5;
    // Add 100 blocks margin to account for block time variance and ensure attestation is
    // reliably expired. This assumed that 100 blocks takes always more than `ATTESTATION_EXPIRY_SECONDS` seconds
    const BLOCKS_TO_FAST_FORWARD: u64 = 100;

    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        ..
    } = init_env(&[SignatureScheme::Secp256k1], PARTICIPANT_COUNT).await;

    let initial_participants = assert_running_return_participants(&contract).await?;
    assert_eq!(initial_participants.participants.len(), PARTICIPANT_COUNT);

    // Calculate expiry timestamp from current block time
    let block_info = worker.view_block().await?;
    let expiry_timestamp = block_info.timestamp() / 1_000_000_000 + ATTESTATION_EXPIRY_SECONDS;

    // Submit an expiring attestation for the last participant
    let target_account = &mpc_signer_accounts[2];
    let internal_participants: Participants = (&initial_participants).into_contract_type();
    let target_node_id = internal_participants
        .get_node_ids()
        .into_iter()
        .find(|node| &node.account_id == target_account.id())
        .expect("target participant not found");

    let expiring_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(expiry_timestamp),
    });

    let submit_result = submit_participant_info(
        target_account,
        &contract,
        &expiring_attestation,
        &target_node_id.tls_public_key.into_interface_type(),
    )
    .await?
    .is_success();
    assert!(submit_result, "failed to submit expiring attestation");

    // Fast-forward past the attestation expiry
    worker.fast_forward(BLOCKS_TO_FAST_FORWARD).await?;
    let block_info = worker.view_block().await?;
    let current_timestamp = block_info.timestamp() / 1_000_000_000;
    // Putting this assertion here such that if the test fails for this reason
    // we already know
    assert!(
        current_timestamp > expiry_timestamp,
        "Going forward {} was not enough: {} {}",
        BLOCKS_TO_FAST_FORWARD,
        current_timestamp,
        expiry_timestamp
    );

    // Call verify_tee() to trigger resharing
    let verify_result = mpc_signer_accounts[0]
        .call(contract.id(), "verify_tee")
        .args_json(serde_json::json!({}))
        .max_gas()
        .transact()
        .await?;
    dbg!(&verify_result);
    assert!(
        verify_result.is_success(),
        "verify_tee call failed: {:?}",
        verify_result
    );

    // Verify contract transitioned to Resharing state
    let state_after_verify = get_state(&contract).await;
    let prospective_epoch_id = match &state_after_verify {
        dtos::ProtocolContractState::Resharing(resharing_state) => {
            mpc_contract::primitives::key_state::EpochId::new(
                resharing_state.resharing_key.epoch_id.0,
            )
        }
        _ => panic!("expected Resharing state, got {:?}", state_after_verify),
    };

    // Complete resharing with the remaining participants (first 2)
    let remaining_accounts = &mpc_signer_accounts[..2];
    conclude_resharing(&contract, remaining_accounts, prospective_epoch_id).await?;

    // Verify final state: 2 participants, target removed
    let final_participants = assert_running_return_participants(&contract).await?;
    assert_eq!(final_participants.participants.len(), PARTICIPANT_COUNT - 1);

    let final_accounts: Vec<String> = final_participants
        .participants
        .iter()
        .map(|(account_id, _, _)| account_id.0.clone())
        .collect();
    let expected_accounts: Vec<String> = remaining_accounts
        .iter()
        .map(|a| a.id().to_string())
        .collect();
    assert_eq!(final_accounts, expected_accounts);

    Ok(())
}
