#![allow(non_snake_case)]

use crate::sandbox::{
    common::{SandboxTestSetup, build_sandbox_node_ids, gen_accounts, submit_tee_attestations},
    utils::{
        consts::{ALL_PROTOCOLS, SUBMIT_PARTICIPANT_INFO_DEPOSIT},
        interface::IntoContractType,
        mpc_contract::{
            assert_running_return_participants, assert_running_return_threshold,
            get_participant_attestation, get_state, get_tee_accounts, submit_participant_info,
            total_gas_fee, vote_add_launcher_hash, vote_for_hash,
        },
        resharing_utils::conclude_resharing,
        sign_utils::DomainResponseTest,
    },
};
use anyhow::Result;
use mpc_contract::primitives::{participants::Participants, test_utils::bogus_ed25519_public_key};
use mpc_primitives::hash::{LauncherDockerComposeHash, LauncherImageHash, NodeImageHash};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::Protocol;
use near_mpc_contract_interface::types::{self as dtos, Attestation, MockAttestation};
use near_workspaces::Contract;
use near_workspaces::types::NearToken;
use rand::SeedableRng;
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
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let threshold = assert_running_return_threshold(&contract).await;

    let allowed_mpc_image_digest = image_digest();

    // Initially, there should be no allowed hashes
    assert_allowed_docker_image_hashes(&contract, &[]).await;

    // First votes - should not be enough
    for account in mpc_signer_accounts.iter().take((threshold.0 - 1) as usize) {
        vote_for_hash(account, &contract, &allowed_mpc_image_digest).await?;
        assert_allowed_docker_image_hashes(&contract, &[]).await;
    }

    // `threshold`-th vote - should reach threshold
    vote_for_hash(
        &mpc_signer_accounts[(threshold.0 - 1) as usize],
        &contract,
        &allowed_mpc_image_digest,
    )
    .await?;
    assert_allowed_docker_image_hashes(&contract, &[allowed_mpc_image_digest]).await;

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
        assert_allowed_docker_image_hashes(&contract, &[allowed_mpc_image_digest]).await;
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
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let threshold = assert_running_return_threshold(&contract).await;
    // This is necessary for some parts of the test below
    assert!((threshold.0 as usize) < mpc_signer_accounts.len());
    let first_hash = image_digest();

    let arbitrary_bytes = [2; 32];
    let second_hash = NodeImageHash::from(arbitrary_bytes);

    // Initially, there should be no allowed hashes
    assert_allowed_docker_image_hashes(&contract, &[]).await;

    // Initial votes for first hash - reach threshold
    for account in mpc_signer_accounts.iter().take(threshold.0 as usize) {
        vote_for_hash(account, &contract, &first_hash).await?;
    }

    // Verify first hash is allowed
    assert_allowed_docker_image_hashes(&contract, &[first_hash]).await;

    // Participant 0 changes vote to second hash
    vote_for_hash(&mpc_signer_accounts[0], &contract, &second_hash).await?;

    // First hash should still be allowed
    // Second hash should not be allowed yet (only 1 vote)
    assert_allowed_docker_image_hashes(&contract, &[first_hash]).await;

    // Participants 2..threshold votes for second hash - should reach threshold
    for account in mpc_signer_accounts
        .iter()
        .skip(2)
        .take(threshold.0 as usize - 1)
    {
        vote_for_hash(account, &contract, &second_hash).await?;
    }

    // Now both hashes should be allowed
    assert_allowed_docker_image_hashes(&contract, &[second_hash, first_hash]).await;

    // Participant 1 also changes vote to second hash
    vote_for_hash(&mpc_signer_accounts[1], &contract, &second_hash).await?;

    // Both hashes should still be allowed (once a hash reaches threshold, it stays)
    // Second hash should still be allowed (threshold + 1 votes)
    assert_allowed_docker_image_hashes(&contract, &[second_hash, first_hash]).await;

    Ok(())
}

/// Tests that vote_code_hash does not accept votes from a randomly generated
/// account id that is not in the participant list
#[tokio::test]
async fn test_vote_code_hash_doesnt_accept_account_id_not_in_participant_list() -> Result<()> {
    let SandboxTestSetup {
        worker, contract, ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let random_account = &gen_accounts(&worker, 1).await.0[0];
    let allowed_mpc_image_digest = image_digest();

    let res = random_account
        .call(contract.id(), method_names::VOTE_CODE_HASH)
        .args_json(serde_json::json!({"code_hash": allowed_mpc_image_digest}))
        .transact()
        .await?;
    let Err(err) = res.into_result() else {
        panic!(
            "vote_code_hash should not accept votes from a randomly generated account id that is not in the participant list"
        );
    };
    let err_str = format!("{:?}", err);
    assert!(
        err_str.contains("NotParticipant"),
        "Expected NotParticipant error, got: {err_str}"
    );
    Ok(())
}

#[tokio::test]
async fn test_vote_code_hash_accepts_allowed_mpc_image_digest_hex_parameter() -> Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let allowed_mpc_image_digest =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    let res = mpc_signer_accounts
        .first()
        .unwrap()
        .call(contract.id(), method_names::VOTE_CODE_HASH)
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
        .call(method_names::ALLOWED_LAUNCHER_COMPOSE_HASHES)
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await?
        .json::<Vec<LauncherDockerComposeHash>>()?)
}

async fn get_allowed_hashes(contract: &Contract) -> Vec<dtos::AllowedMpcDockerImageHash> {
    contract
        .call(method_names::ALLOWED_DOCKER_IMAGE_HASHES)
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await
        .expect("Contract is running")
        .json()
        .expect("allowed_docker_image_hashes method is infallible")
}

async fn assert_allowed_docker_image_hashes(contract: &Contract, expected: &[NodeImageHash]) {
    let entries = get_allowed_hashes(contract).await;

    let hashes: Vec<NodeImageHash> = entries.iter().map(|entry| entry.image_hash).collect();
    assert_eq!(hashes, expected);

    let Some((newest, superseded)) = entries.split_first() else {
        return;
    };
    assert_eq!(newest.expiry_timestamp_seconds, None);

    let expiries: Vec<u64> = superseded
        .iter()
        .map(|entry| {
            entry
                .expiry_timestamp_seconds
                .expect("superseded hashes have an eviction time")
        })
        .collect();
    assert!(
        expiries.is_sorted_by(|a, b| a >= b),
        "eviction times must be descending, got {expiries:?}"
    );
}

pub async fn get_participants(contract: &Contract) -> Result<usize> {
    let state = contract
        .call(method_names::STATE)
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await?;
    let value: dtos::ProtocolContractStateCompat = state.json()?;
    let dtos::ProtocolContractStateCompat::Running(running) = value else {
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
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let success = submit_participant_info(
        &mpc_signer_accounts[0],
        &contract,
        &Attestation::Mock(MockAttestation::Valid),
        &p2p_tls_key().into(),
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
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    // Create a new account that's not the contract
    let external_account = worker.dev_create_account().await?;

    // Try to call clean_tee_status from external account - should fail
    let result = external_account
        .call(contract.id(), method_names::CLEAN_TEE_STATUS)
        .args_json(serde_json::json!({}))
        .transact()
        .await?;

    // The call should fail because it's not from the contract itself
    assert!(!result.is_success());

    // Verify the error message indicates unauthorized access
    let failure = result
        .into_result()
        .expect_err("clean_tee_status must reject a non-private caller");
    assert!(format!("{failure:?}").contains("Method clean_tee_status is private"));

    Ok(())
}

/// **`clean_tee_status` when called by the contract itself** — the call succeeds and the
/// endpoint leaves `stored_attestations` untouched. Attestation pruning is handled by the
/// separate `clean_invalid_attestations` endpoint.
#[tokio::test]
async fn clean_tee_status__should_succeed_when_contract_calls_itself_and_leave_attestations_alone()
-> Result<()> {
    // Given
    let SandboxTestSetup {
        worker,
        contract,
        mut mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    let participants: Participants =
        (&assert_running_return_participants(&contract).await?).into_contract_type();
    let participant_uids = build_sandbox_node_ids(&participants, &mpc_signer_accounts);
    submit_tee_attestations(&contract, &mut mpc_signer_accounts, &participant_uids).await?;

    // Verify current participants have TEE data
    assert_eq!(get_tee_accounts(&contract).await?, participant_uids);

    // Create additional accounts (non-participants) and submit TEE info for them
    const NUM_ADDITIONAL_ACCOUNTS: usize = 2;
    let (mut additional_accounts, additional_participants) =
        gen_accounts(&worker, NUM_ADDITIONAL_ACCOUNTS).await;
    let additional_uids = build_sandbox_node_ids(&additional_participants, &additional_accounts);
    submit_tee_attestations(&contract, &mut additional_accounts, &additional_uids).await?;

    // Verify we have TEE data for all accounts before cleanup
    let tee_participants_before = get_tee_accounts(&contract).await?;
    let expected_union = &additional_uids | &participant_uids;
    assert_eq!(tee_participants_before, expected_union);

    // When: contract calls clean_tee_status on itself.
    let result = contract
        .as_account()
        .call(contract.id(), method_names::CLEAN_TEE_STATUS)
        .args_json(serde_json::json!({}))
        .transact()
        .await?;

    assert!(result.is_success());

    // Then: stored attestations are unchanged — vote-only cleanup.
    let tee_participants_after = get_tee_accounts(&contract).await?;
    assert_eq!(tee_participants_after, expected_union);

    Ok(())
}

/// **`clean_invalid_attestations` end-to-end** — an attestation whose expiry has passed
/// is evicted from `stored_attestations` when the endpoint is invoked. Restores the
/// functional cleanup-path coverage previously asserted via `clean_tee_status`.
#[tokio::test]
async fn clean_invalid_attestations__should_remove_expired_entries() -> Result<()> {
    // `verify()` at insert time rejects attestations that are already expired, so the
    // expiring attestation is submitted with an expiry a few seconds in the future and
    // the test then fast-forwards past it. 100 blocks is enough that the block
    // timestamp reliably advances past a 5-second expiry window.
    const ATTESTATION_EXPIRY_SECONDS: u64 = 5;
    const BLOCKS_TO_FAST_FORWARD: u64 = 100;

    // Given
    let SandboxTestSetup {
        worker,
        contract,
        mut mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    // Submit a structurally-valid attestation for every current participant so those
    // entries survive the sweep.
    let participants: Participants =
        (&assert_running_return_participants(&contract).await?).into_contract_type();
    let participant_uids = build_sandbox_node_ids(&participants, &mpc_signer_accounts);
    submit_tee_attestations(&contract, &mut mpc_signer_accounts, &participant_uids).await?;

    // Submit an attestation from a non-participant that will expire shortly.
    let (stale_accounts, _stale_participants) = gen_accounts(&worker, 1).await;
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
    let submit_result = submit_participant_info(
        stale_account,
        &contract,
        &expiring_attestation,
        &stale_tls_key,
    )
    .await?;
    assert!(submit_result.is_success());

    let before_cleanup = get_tee_accounts(&contract).await?;
    assert_eq!(before_cleanup.len(), participant_uids.len() + 1);

    // Advance past the expiry.
    worker.fast_forward(BLOCKS_TO_FAST_FORWARD).await?;

    // When: any account calls `clean_invalid_attestations` with a scan budget large enough
    // to cover every stored entry.
    let scan_budget: u32 = (before_cleanup.len() as u32) + 1;
    let result = contract
        .as_account()
        .call(contract.id(), method_names::CLEAN_INVALID_ATTESTATIONS)
        .args_json(serde_json::json!({ "max_scan": scan_budget }))
        .transact()
        .await?;
    assert!(result.is_success());

    // Then: the expired entry is evicted while the valid participant entries remain.
    let after_cleanup = get_tee_accounts(&contract).await?;
    assert_eq!(after_cleanup, participant_uids);

    Ok(())
}

#[tokio::test]
async fn new_hash_and_previous_hashes_under_grace_period_pass_attestation_verification()
-> Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let threshold = assert_running_return_threshold(&contract).await;
    let hash_1 = [1; 32];
    let hash_2 = [2; 32];
    let hash_3 = [3; 32];

    let participant_account_1 = &mpc_signer_accounts[0];

    // Initially, there should be no allowed hashes
    assert_allowed_docker_image_hashes(&contract, &[]).await;

    let hashes = [hash_1, hash_2, hash_3];

    for (i, current_hash) in hashes.iter().enumerate() {
        let hash = NodeImageHash::from(*current_hash);
        for account in mpc_signer_accounts.iter().take(threshold.0 as usize) {
            vote_for_hash(account, &contract, &hash).await?;
        }

        let previous_and_current_approved_hashes = &hashes[..=i];

        for approved_hash in previous_and_current_approved_hashes {
            let mock_attestation = MockAttestation::WithConstraints {
                mpc_docker_image_hash: Some((*approved_hash).into()),
                launcher_docker_compose_hash: None,
                expiry_timestamp_seconds: None,
                expected_measurements: None,
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
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

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
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

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
        expected_measurements: None,
    });

    let participant_2_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(u64::MAX - 1),
        expected_measurements: None,
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
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    let participant_account = &mpc_signer_accounts[0];
    let tls_key = bogus_ed25519_public_key();

    let first_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(u64::MAX),
        expected_measurements: None,
    });

    let second_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(u64::MAX - 1),
        expected_measurements: None,
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

/// Tests that on a fresh contract, compose hashes are derived when both an MPC image
/// hash and a launcher image hash are voted in.
#[tokio::test]
async fn test_function_allowed_launcher_compose_hashes() -> anyhow::Result<()> {
    let SandboxTestSetup {
        contract,
        mpc_signer_accounts,
        ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;

    assert_eq!(
        get_allowed_launcher_compose_hashes(&contract).await?.len(),
        0
    );

    // Vote in an MPC image hash — no compose hashes yet (no launcher images)
    let allowed_mpc_image_digest = image_digest();
    for account in &mpc_signer_accounts {
        vote_for_hash(account, &contract, &allowed_mpc_image_digest).await?;
    }
    assert_eq!(
        get_allowed_launcher_compose_hashes(&contract).await?.len(),
        0,
        "no compose hashes without a launcher image"
    );

    // Vote in a launcher image hash — compose hash derived for the existing MPC image
    let launcher_hash = LauncherImageHash::from([0xAA; 32]);
    for account in &mpc_signer_accounts {
        vote_add_launcher_hash(account, &contract, &launcher_hash).await?;
    }
    assert_eq!(
        get_allowed_launcher_compose_hashes(&contract).await?.len(),
        1,
        "1 compose hash: launcher x MPC image"
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
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .with_number_of_participants(PARTICIPANT_COUNT)
        .build()
        .await;

    let initial_participants = assert_running_return_participants(&contract).await?;
    assert_eq!(initial_participants.participants.len(), PARTICIPANT_COUNT);

    // Calculate expiry timestamp from current block time
    let block_info = worker.view_block().await?;
    let expiry_timestamp = block_info.timestamp() / 1_000_000_000 + ATTESTATION_EXPIRY_SECONDS;

    // Submit an expiring attestation for the last participant
    let target_account = &mpc_signer_accounts[2];
    let internal_participants: Participants = (&initial_participants).into_contract_type();
    let target_node_id = build_sandbox_node_ids(&internal_participants, &mpc_signer_accounts)
        .into_iter()
        .find(|node| node.account_id == *target_account.id())
        .expect("target participant not found");

    let expiring_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(expiry_timestamp),
        expected_measurements: None,
    });

    let submit_result = submit_participant_info(
        target_account,
        &contract,
        &expiring_attestation,
        &target_node_id.tls_public_key,
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
        .call(contract.id(), method_names::VERIFY_TEE)
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
        dtos::ProtocolContractStateCompat::Resharing(resharing_state) => {
            resharing_state.resharing_key.epoch_id
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
        .map(|(account_id, _, _)| account_id.to_string())
        .collect();
    let expected_accounts: Vec<String> = remaining_accounts
        .iter()
        .map(|a| a.id().to_string())
        .collect();
    assert_eq!(final_accounts, expected_accounts);

    Ok(())
}

/// Complements [`test_verify_tee_expired_attestation_triggers_resharing`]: when kicking out the
/// participants with expired attestations would leave fewer than `threshold` participants with a
/// valid TEE status, the contract must NOT remove anyone (that would permanently break the
/// network). Instead every participant is kept and the network stops accepting signature requests.
///
/// Steps:
/// 1. Initialize contract with 3 participants (threshold 2).
/// 2. Expire the attestations of 2 of the 3 participants, leaving only 1 valid (< threshold).
/// 3. Fast-forward blocks past the attestation expiry.
/// 4. Call `verify_tee()`, which returns `false` and does NOT enter resharing.
/// 5. Verify the contract stays Running with all 3 participants (no kickout).
/// 6. Verify a `sign` request is now refused with the TEE-validation-failed error.
#[tokio::test]
async fn verify_tee__should_keep_participants_and_stop_signing_when_kickout_drops_below_threshold()
-> Result<()> {
    // Given
    const PARTICIPANT_COUNT: usize = 3;
    const ATTESTATION_EXPIRY_SECONDS: u64 = 5;
    // 100 blocks reliably advances the block timestamp past the 5-second expiry window.
    const BLOCKS_TO_FAST_FORWARD: u64 = 100;

    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = SandboxTestSetup::builder()
        .with_protocols(&[Protocol::CaitSith])
        .with_number_of_participants(PARTICIPANT_COUNT)
        .build()
        .await;

    let threshold = assert_running_return_threshold(&contract).await;
    let initial_participants = assert_running_return_participants(&contract).await?;
    assert_eq!(initial_participants.participants.len(), PARTICIPANT_COUNT);

    // Expire all but `threshold - 1` attestations, leaving the valid set exactly one
    // below threshold regardless of the participant/threshold constants above.
    let remaining_valid = threshold.0 as usize - 1;
    assert!(
        remaining_valid < threshold.0 as usize,
        "test precondition: surviving participants ({remaining_valid}) must be below threshold ({})",
        threshold.0
    );

    // Compute the expiry timestamp from the current block time.
    let block_info = worker.view_block().await?;
    let expiry_timestamp = block_info.timestamp() / 1_000_000_000 + ATTESTATION_EXPIRY_SECONDS;
    let expiring_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_timestamp_seconds: Some(expiry_timestamp),
        expected_measurements: None,
    });

    // Submit an expiring attestation for every participant past the first `remaining_valid`.
    let internal_participants: Participants = (&initial_participants).into_contract_type();
    let node_ids = build_sandbox_node_ids(&internal_participants, &mpc_signer_accounts);
    for target_account in &mpc_signer_accounts[remaining_valid..] {
        let target_node_id = node_ids
            .iter()
            .find(|node| node.account_id == *target_account.id())
            .expect("target participant not found");
        let submit_success = submit_participant_info(
            target_account,
            &contract,
            &expiring_attestation,
            &target_node_id.tls_public_key,
        )
        .await?
        .is_success();
        assert!(submit_success, "failed to submit expiring attestation");
    }

    // Fast-forward past the attestation expiry.
    worker.fast_forward(BLOCKS_TO_FAST_FORWARD).await?;
    let current_timestamp = worker.view_block().await?.timestamp() / 1_000_000_000;
    assert!(
        current_timestamp > expiry_timestamp,
        "fast-forwarding {BLOCKS_TO_FAST_FORWARD} blocks was not enough: {current_timestamp} {expiry_timestamp}"
    );

    // When: a participant calls verify_tee while too few valid attestations remain.
    let verify_result = mpc_signer_accounts[0]
        .call(contract.id(), method_names::VERIFY_TEE)
        .args_json(serde_json::json!({}))
        .max_gas()
        .transact()
        .await?;
    assert!(
        verify_result.is_success(),
        "verify_tee call failed: {verify_result:?}"
    );

    // Then: verify_tee reports the network is no longer accepting requests.
    let accepting_requests: bool = verify_result.json()?;
    assert!(
        !accepting_requests,
        "verify_tee should return false when fewer than threshold participants remain valid"
    );

    // Then: no participant is kicked out — the contract stays Running with all participants.
    let state_after_verify = get_state(&contract).await;
    let dtos::ProtocolContractStateCompat::Running(running_after) = &state_after_verify else {
        panic!("expected Running state (no resharing), got {state_after_verify:?}");
    };
    assert_eq!(
        running_after.parameters.participants.participants.len(),
        PARTICIPANT_COUNT,
        "no participant should be removed when kickout would drop below threshold"
    );

    // Then: signature requests are refused while the TEE validation is degraded.
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let requester = &mpc_signer_accounts[0];
    let DomainResponseTest::Sign(sign_request) = DomainResponseTest::new(
        &mut rng,
        keys.first().expect("CaitSith sign domain exists"),
        requester.id(),
    ) else {
        panic!("CaitSith domain must yield a sign request");
    };
    let sign_result = requester
        .call(contract.id(), method_names::SIGN)
        .args_json(sign_request.request_json_args())
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
        .await?;
    let Err(sign_err) = sign_result.into_result() else {
        panic!("sign request must be refused while the network is not accepting requests");
    };
    let sign_err = format!("{sign_err:?}");
    assert!(
        sign_err.contains("not accepting new requests"),
        "expected TEE-validation-failed rejection, got: {sign_err}"
    );

    Ok(())
}

/// A submission attaching less than the flat storage fee is rejected before the
/// entry is stored.
#[tokio::test]
async fn submit_participant_info__should_reject_new_attestation_below_flat_fee() -> Result<()> {
    // Given
    let SandboxTestSetup {
        worker, contract, ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let outsider = worker.dev_create_account().await?;
    let fresh_tls_key = bogus_ed25519_public_key();
    let storage_before = worker.view_account(contract.id()).await?.storage_usage;
    let below_fee = SUBMIT_PARTICIPANT_INFO_DEPOSIT.saturating_sub(NearToken::from_yoctonear(1));

    // When
    let result = outsider
        .call(contract.id(), method_names::SUBMIT_PARTICIPANT_INFO)
        .args_json((
            Attestation::Mock(MockAttestation::Valid),
            fresh_tls_key.clone(),
        ))
        .deposit(below_fee)
        .max_gas()
        .transact()
        .await?;

    // Then
    assert!(
        !result.is_success(),
        "submission below the flat fee must fail: {result:?}"
    );
    let error_msg = format!("{:?}", result.into_result());
    assert!(
        error_msg.contains("Attached deposit is lower than required"),
        "expected an insufficient-deposit error, got: {error_msg}"
    );
    let stored = get_participant_attestation(&contract, &fresh_tls_key).await?;
    assert!(
        stored.is_none(),
        "no attestation should be stored when the deposit is rejected"
    );
    let storage_after = worker.view_account(contract.id()).await?.storage_usage;
    assert_eq!(
        storage_after, storage_before,
        "contract storage must not grow when the submission is rejected"
    );
    Ok(())
}

/// A submission attaching exactly the flat fee is stored, and the caller is
/// charged the whole fee with no excess refunded (the fee far exceeds the true
/// storage cost by design).
#[tokio::test]
async fn submit_participant_info__should_store_new_attestation_and_charge_the_flat_fee()
-> Result<()> {
    // Given
    let SandboxTestSetup {
        worker, contract, ..
    } = SandboxTestSetup::builder()
        .with_protocols(ALL_PROTOCOLS)
        .build()
        .await;
    let outsider = worker.dev_create_account().await?;
    let fresh_tls_key = bogus_ed25519_public_key();
    let balance_before = outsider.view_account().await?.balance;

    // When
    let result = submit_participant_info(
        &outsider,
        &contract,
        &Attestation::Mock(MockAttestation::Valid),
        &fresh_tls_key,
    )
    .await?;

    // Then
    assert!(
        result.is_success(),
        "submission attaching the flat fee should succeed: {result:?}"
    );
    let stored = get_participant_attestation(&contract, &fresh_tls_key).await?;
    assert!(
        stored.is_some(),
        "the attestation entry should be stored on-chain"
    );
    let balance_after = outsider.view_account().await?.balance;
    let net_spent = balance_before.saturating_sub(balance_after);
    let non_gas_spent = net_spent.saturating_sub(total_gas_fee(&result));
    assert_eq!(non_gas_spent, SUBMIT_PARTICIPANT_INFO_DEPOSIT);
    Ok(())
}
