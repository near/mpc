use dtos_contract::{Attestation, Ed25519PublicKey, MockAttestation};
use mpc_contract::{
    config::InitConfig,
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        key_state::{AttemptId, EpochId, KeyEventId, KeyForDomain, Keyset},
        participants::{ParticipantId, ParticipantInfo},
        test_utils::{bogus_ed25519_near_public_key, gen_participants},
        thresholds::{Threshold, ThresholdParameters},
    },
    state::ProtocolContractState,
    tee::tee_state::NodeId,
    MpcContract,
};

use assert_matches::assert_matches;
use mpc_primitives::hash::MpcDockerImageHash;
use near_sdk::{
    test_utils::VMContextBuilder, testing_env, AccountId, CurveType, NearToken, PublicKey,
    VMContext,
};
use std::time::Duration;

const NANO: u64 = 1_000_000_000;

struct TestSetup {
    contract: MpcContract,
    participants_list: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
}

impl TestSetup {
    fn new(participant_count: usize, threshold: u64, init_config: Option<InitConfig>) -> Self {
        let participants = gen_participants(participant_count);
        let participants_list = participants.participants().clone();
        let contract = {
            let parameters =
                ThresholdParameters::new(participants, Threshold::new(threshold)).unwrap();
            let keyset = Keyset::new(
                EpochId::new(5),
                vec![KeyForDomain {
                    domain_id: DomainId::default(),
                    key: PublicKeyExtended::Secp256k1 {
                        near_public_key: PublicKey::from_parts(CurveType::SECP256K1, vec![1u8; 64])
                            .unwrap(),
                    },
                    attempt: AttemptId::new(),
                }],
            );
            let domains = vec![DomainConfig {
                id: DomainId::default(),
                scheme: SignatureScheme::Secp256k1,
            }];
            MpcContract::init_running(domains, 1, keyset, parameters, init_config).unwrap()
        };

        Self {
            contract,
            participants_list,
        }
    }

    fn submit_attestation_for_node(&mut self, node_id: &NodeId, attestation: Attestation) {
        let context = create_context_for_participant(&node_id.account_id);
        testing_env!(context);
        let tls_key_bytes: [u8; 32] = node_id.tls_public_key.as_bytes()[1..].try_into().unwrap();
        self.contract
            .submit_participant_info(attestation, Ed25519PublicKey::from(tls_key_bytes))
            .unwrap();
    }
}

/// **Integration test for participant kickout after expiration** - Tests expired attestation removal. This test demonstrates the complete kickout mechanism using direct contract calls:
/// 1. Initialize contract with 3 secp256k1 participants in Running state at time T=1s
/// 2. Submit valid attestations for first 2 participants at time T=1s
/// 3. Submit expiring attestation for 3rd participant with expiry at time T+10s
/// 4. Fast-forward blockchain time to T+20s using VMContextBuilder
/// 5. Call verify_tee() which detects expired attestation and returns false
/// 6. Contract automatically transitions from Running to Resharing state
/// 7. Start resharing instance and have valid participants vote for completion
/// 8. Contract transitions back to Running state with filtered participant set (2 participants)
/// 9. Verify final state: 2 participants in Running state but 3 TEE accounts remain (cleanup tested separately)
#[test]
fn test_participant_kickout_after_expiration() {
    const INITIAL_TIME_SECONDS: u64 = 1;
    const INITIAL_TIMESTAMP_NANOS: u64 =
        Duration::from_secs(INITIAL_TIME_SECONDS).as_nanos() as u64;
    const PARTICIPANT_COUNT: usize = 3;
    const THRESHOLD: u64 = 2;
    const EXPIRY_OFFSET_SECONDS: u64 = 10; // Attestation expires 10 seconds after start
    const POST_EXPIRY_WAIT_SECONDS: u64 = 20; // Wait 20 seconds after start to trigger resharing

    testing_env!(VMContextBuilder::new()
        .block_timestamp(INITIAL_TIMESTAMP_NANOS)
        .build());
    let domain_id = DomainId::default();

    let mut setup = TestSetup::new(PARTICIPANT_COUNT, THRESHOLD, None);

    assert_eq!(setup.contract.get_tee_accounts().len(), 0);

    // Submit valid attestations for first 2 participants
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);
    let participant_nodes: Vec<NodeId> = setup
        .participants_list
        .iter()
        .take(2)
        .cloned()
        .map(|(account_id, _, participant_info)| NodeId {
            account_id,
            tls_public_key: participant_info.sign_pk,
        })
        .collect();

    for node_id in &participant_nodes {
        setup.submit_attestation_for_node(node_id, valid_attestation.clone());
    }

    // Submit expiring attestation for 3rd participant
    const EXPIRY_SECONDS: u64 = INITIAL_TIME_SECONDS + EXPIRY_OFFSET_SECONDS;
    let expiring_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_time_stamp_seconds: Some(EXPIRY_SECONDS),
    });
    let third_node = NodeId {
        account_id: setup.participants_list[2].0.clone(),
        tls_public_key: setup.participants_list[2].2.sign_pk.clone(),
    };

    setup.submit_attestation_for_node(&third_node, expiring_attestation);

    assert_eq!(setup.contract.get_tee_accounts().len(), PARTICIPANT_COUNT);

    // Fast-forward time past expiry and trigger resharing
    const EXPIRED_TIMESTAMP: u64 =
        INITIAL_TIMESTAMP_NANOS + Duration::from_secs(POST_EXPIRY_WAIT_SECONDS).as_nanos() as u64;
    testing_env!(VMContextBuilder::new()
        .block_timestamp(EXPIRED_TIMESTAMP)
        .build());

    assert!(setup.contract.verify_tee().unwrap());

    let resharing_state = match setup.contract.state() {
        ProtocolContractState::Resharing(r) => r,
        state => panic!("Should be in Resharing state. Actual state {:#?}", state),
    };

    // Complete resharing process
    let key_event_id = KeyEventId::new(
        resharing_state.prospective_epoch_id(),
        domain_id,
        AttemptId::new(),
    );

    testing_env!(create_context_for_participant(
        &participant_nodes[0].account_id
    ));
    setup.contract.start_reshare_instance(key_event_id).unwrap();

    // Vote for resharing with first 2 participants
    for node_id in &participant_nodes {
        testing_env!(create_context_for_participant(&node_id.account_id));
        setup.contract.vote_reshared(key_event_id).unwrap();
    }

    // Verify final state: back to Running with one less participant
    assert_matches!(setup.contract.state(), ProtocolContractState::Running(_));

    // At this point we have 2 participants in Running state but 3 TEE accounts
    // The cleanup step is tested separately in test_clean_tee_status_removes_non_participants
    let final_running_state = match setup.contract.state() {
        ProtocolContractState::Running(r) => r,
        _ => panic!("Should be in Running state after resharing"),
    };

    const EXPECTED_PARTICIPANT_COUNT: usize = PARTICIPANT_COUNT - 1;
    assert_eq!(
        final_running_state.parameters.participants().len(),
        EXPECTED_PARTICIPANT_COUNT
    );
    // Before clean_tee_status() cleanup, we still have old TEE accounts
    assert_eq!(setup.contract.get_tee_accounts().len(), PARTICIPANT_COUNT);
}

/// ** Test for TEE cleanup of non-participants** - Tests that `clean_tee_status()` removes
/// TEE accounts for accounts that are no longer in the participant list.
/// This simulates cleanup after participant removal (e.g., post-resharing).
#[test]
fn test_clean_tee_status_removes_non_participants() {
    const PARTICIPANT_COUNT: usize = 2; // After resharing removed one participant
    const THRESHOLD: u64 = 2;

    testing_env!(VMContextBuilder::new()
        .attached_deposit(NearToken::from_near(1))
        .build());

    // Create contract in Running state with 2 current participants
    let mut setup = TestSetup::new(PARTICIPANT_COUNT, THRESHOLD, None);

    // Submit TEE info for current 2 participants (all have valid attestations)
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);
    let participant_nodes: Vec<NodeId> = setup
        .participants_list
        .iter()
        .take(2)
        .cloned()
        .map(|(account_id, _, participant_info)| NodeId {
            account_id,
            tls_public_key: participant_info.sign_pk,
        })
        .collect();

    for node_id in &participant_nodes {
        setup.submit_attestation_for_node(node_id, valid_attestation.clone());
    }

    // Add TEE account for someone who is NOT a current participant
    // (simulates leftover data from a participant who was removed during resharing)
    let removed_participant_node = NodeId {
        account_id: "removed.participant.near".parse().unwrap(),
        tls_public_key: bogus_ed25519_near_public_key(),
    };

    setup.submit_attestation_for_node(&removed_participant_node, valid_attestation);

    // Verify initial state: 2 participants but 3 TEE accounts
    const INITIAL_TEE_ACCOUNTS: usize = PARTICIPANT_COUNT + 1; // 2 current + 1 stale
    assert_eq!(
        setup.contract.get_tee_accounts().len(),
        INITIAL_TEE_ACCOUNTS
    );

    let running_state = match setup.contract.state() {
        ProtocolContractState::Running(r) => r,
        _ => panic!("Should be in Running state"),
    };
    assert_eq!(
        running_state.parameters.participants().len(),
        PARTICIPANT_COUNT
    );

    // Test cleanup: should remove TEE account for non-participant
    setup.contract.clean_tee_status().unwrap();

    // Verify cleanup worked: TEE accounts reduced to match participant count
    assert_eq!(setup.contract.get_tee_accounts().len(), PARTICIPANT_COUNT);

    // State should remain Running with same participant count
    let final_running_state = match setup.contract.state() {
        ProtocolContractState::Running(r) => r,
        _ => panic!("Should still be Running after cleanup"),
    };
    assert_eq!(
        final_running_state.parameters.participants().len(),
        PARTICIPANT_COUNT
    );
}

#[test]
fn only_latest_hash_after_grace_period() {
    // Use descriptive timing constants
    const FIRST_ENTRY_TIME_NANO_SECONDS: u64 = NANO; // 1 second
    const GRACE_PERIOD_NANO_SECONDS: u64 = 10 * NANO; // 10 seconds
    const DELAY_BETWEEN_HASH_VOTES: u64 = 3 * NANO; // 3 seconds

    const PARTICIPANT_COUNT: usize = 3;
    const THRESHOLD: u64 = 2;

    testing_env!(VMContextBuilder::new()
        .block_timestamp(FIRST_ENTRY_TIME_NANO_SECONDS)
        .build());

    let init_config = InitConfig {
        tee_upgrade_deadline_duration_seconds: Some(GRACE_PERIOD_NANO_SECONDS / NANO),
        ..Default::default()
    };

    let mut test_setup = TestSetup::new(PARTICIPANT_COUNT, THRESHOLD, Some(init_config));

    // Two distinct code hashes
    let old_code_hash_bytes = [1; 32];
    let new_code_hash_bytes = [2; 32];

    for (account_id, _participant_id, _) in &test_setup.participants_list {
        testing_env!(VMContextBuilder::new()
            .block_timestamp(FIRST_ENTRY_TIME_NANO_SECONDS)
            .signer_account_id(account_id.clone())
            .build());

        test_setup
            .contract
            .vote_code_hash(old_code_hash_bytes.into())
            .unwrap();
    }

    let time_of_new_vote = FIRST_ENTRY_TIME_NANO_SECONDS + DELAY_BETWEEN_HASH_VOTES;

    for (account_id, _participant_id, _) in &test_setup.participants_list {
        testing_env!(VMContextBuilder::new()
            .block_timestamp(time_of_new_vote)
            .signer_account_id(account_id.clone())
            .build());

        test_setup
            .contract
            .vote_code_hash(new_code_hash_bytes.into())
            .unwrap();
    }

    // The grace period deadline should be defined in terms of the insertion time of the successor hash.
    let grace_period_deadline = time_of_new_vote + GRACE_PERIOD_NANO_SECONDS;

    // Exactly at the deadline of the grace period both hashes are allowed.
    testing_env!(VMContextBuilder::new()
        .block_timestamp(grace_period_deadline)
        .build());

    let _: [_; 2] = test_setup.contract.allowed_code_hashes().try_into().expect(
        "Both hashes should still be allowed during the grace period (at the deadline instant)",
    );

    // One nanosecond after the grace period ends only the latest image hash is allowed.
    testing_env!(VMContextBuilder::new()
        .block_timestamp(grace_period_deadline + 1)
        .build());

    let remaining_allowed: [_; 1] = test_setup
        .contract
        .allowed_code_hashes()
        .try_into()
        .expect("After the grace period, only the most recent code hash should remain");

    let remaining_hash_bytes = *remaining_allowed[0];

    assert_eq!(
        remaining_hash_bytes,
        new_code_hash_bytes,
        "The latest voted image hash should be the sole allowed hash after the grace period elapses"
    );
}

#[test]
fn latest_inserted_image_hash_takes_precedence_on_equal_time_stamps() {
    const INITIAL_TIME_NANO_SECONDS: u64 = 1;
    const GRACE_PERIOD_SECONDS: u64 = 10;

    const PARTICIPANT_COUNT: usize = 3;
    const THRESHOLD: u64 = 2;

    testing_env!(VMContextBuilder::new()
        .block_timestamp(INITIAL_TIME_NANO_SECONDS)
        .build());

    let init_config = InitConfig {
        tee_upgrade_deadline_duration_seconds: Some(GRACE_PERIOD_SECONDS),
        ..Default::default()
    };

    let mut setup = TestSetup::new(PARTICIPANT_COUNT, THRESHOLD, Some(init_config));

    let hash_1 = [1; 32];
    let hash_2 = [2; 32];
    let hash_3 = [3; 32];

    for code_hash in [hash_1, hash_2, hash_3] {
        for (account_id, _, _) in &setup.participants_list {
            testing_env!(VMContextBuilder::new()
                .block_timestamp(INITIAL_TIME_NANO_SECONDS)
                .signer_account_id(account_id.clone())
                .build());

            setup.contract.vote_code_hash(code_hash.into()).unwrap();
        }
    }

    testing_env!(VMContextBuilder::new().block_timestamp(u64::MAX).build());

    let allowed_code_hashes: [_; 1] = setup
        .contract
        .allowed_code_hashes()
        .try_into()
        .expect("1 second after expiry both old image hashes are expired");

    let [allowed_code_hash] = allowed_code_hashes;
    let allowed_code_hash_bytes: [u8; 32] = *allowed_code_hash;

    assert_eq!(allowed_code_hash_bytes, hash_3, "Hash3 was the latest vote image hash and should be the only allowed image hash after the grace period has passed");
}

/// Verifies that when three hashes are added at different times,
/// each hash’s grace period is determined by the insertion time of its
/// immediate successor, not the latest hash overall.
#[test]
fn hash_grace_period_depends_on_successor_entry_time_not_latest() {
    // Timing constants
    const FIRST_ENTRY_TIME: u64 = NANO; // 1 second
    const SECOND_ENTRY_DELAY: u64 = 3 * NANO; // 3 seconds later
    const THIRD_ENTRY_DELAY: u64 = 6 * NANO; // 6 seconds later
    const GRACE_PERIOD: u64 = 10 * NANO; // 10 seconds

    const PARTICIPANT_COUNT: usize = 3;
    const THRESHOLD: u64 = 2;

    testing_env!(VMContextBuilder::new()
        .block_timestamp(FIRST_ENTRY_TIME)
        .build());

    let init_config = InitConfig {
        tee_upgrade_deadline_duration_seconds: Some(GRACE_PERIOD / NANO),
        ..Default::default()
    };

    let mut test_setup = TestSetup::new(PARTICIPANT_COUNT, THRESHOLD, Some(init_config));

    // Distinct hashes
    let first_hash = [1; 32];
    let second_hash = [2; 32];
    let third_hash = [3; 32];

    // All participants vote for the first hash at FIRST_ENTRY_TIME
    for (account_id, _, _) in &test_setup.participants_list {
        testing_env!(VMContextBuilder::new()
            .block_timestamp(FIRST_ENTRY_TIME)
            .signer_account_id(account_id.clone())
            .build());

        test_setup
            .contract
            .vote_code_hash(first_hash.into())
            .unwrap();
    }

    let second_entry_time = FIRST_ENTRY_TIME + SECOND_ENTRY_DELAY;

    // All participants vote for the second hash at SECOND_ENTRY_TIME
    for (account_id, _, _) in &test_setup.participants_list {
        testing_env!(VMContextBuilder::new()
            .block_timestamp(second_entry_time)
            .signer_account_id(account_id.clone())
            .build());

        test_setup
            .contract
            .vote_code_hash(second_hash.into())
            .unwrap();
    }

    let third_entry_time = FIRST_ENTRY_TIME + THIRD_ENTRY_DELAY;

    // All participants vote for the third hash at THIRD_ENTRY_TIME
    for (account_id, _, _) in &test_setup.participants_list {
        testing_env!(VMContextBuilder::new()
            .block_timestamp(third_entry_time)
            .signer_account_id(account_id.clone())
            .build());

        test_setup
            .contract
            .vote_code_hash(third_hash.into())
            .unwrap();
    }

    // The first hash should expire at (second_entry_time + GRACE_PERIOD),
    // regardless of the third entry.
    let first_hash_deadline = second_entry_time + GRACE_PERIOD;

    // One nanosecond after deadline the first hash must be gone
    testing_env!(VMContextBuilder::new()
        .block_timestamp(first_hash_deadline + 1)
        .build());

    let allowed_after_deadline = test_setup.contract.allowed_code_hashes();
    let expected_allowed_hashes: Vec<MpcDockerImageHash> =
        vec![second_hash.into(), third_hash.into()];

    assert_eq!(
        expected_allowed_hashes, allowed_after_deadline,
        "First hash should expire immediately after its grace period deadline"
    );

    let second_hash_deadline = third_entry_time + GRACE_PERIOD;

    testing_env!(VMContextBuilder::new()
        .block_timestamp(second_hash_deadline)
        .build());

    let allowed_before_second_expiry = test_setup.contract.allowed_code_hashes();
    assert_eq!(
        expected_allowed_hashes, allowed_before_second_expiry,
        "Second hash should still be allowed until its own successor-based grace period ends"
    );

    testing_env!(VMContextBuilder::new()
        .block_timestamp(second_hash_deadline + 1)
        .build());

    let expected_allowed_hashes: Vec<MpcDockerImageHash> = vec![third_hash.into()];
    let allowed_before_second_expiry = test_setup.contract.allowed_code_hashes();
    assert_eq!(
        expected_allowed_hashes, allowed_before_second_expiry,
        "Second hash should still be allowed until its own successor-based grace period ends"
    );
}

#[test]
fn latest_image_never_expires_if_its_not_superseded() {
    const START_TIME_SECONDS: u64 = 1;
    const GRACE_PERIOD_SECONDS: u64 = 10;
    const PARTICIPANT_COUNT: usize = 3;
    const VOTE_THRESHOLD: u64 = 2;

    testing_env!(VMContextBuilder::new()
        .block_timestamp(START_TIME_SECONDS * NANO)
        .build());

    let init_config = InitConfig {
        tee_upgrade_deadline_duration_seconds: Some(GRACE_PERIOD_SECONDS),
        ..Default::default()
    };
    let mut setup = TestSetup::new(PARTICIPANT_COUNT, VOTE_THRESHOLD, Some(init_config));

    let only_image_hash = [123; 32];

    // Vote-in once
    for (account_id, _, _) in setup.participants_list.iter().take(2) {
        testing_env!(VMContextBuilder::new()
            .block_timestamp(START_TIME_SECONDS * NANO)
            .signer_account_id(account_id.clone())
            .build());
        setup
            .contract
            .vote_code_hash(only_image_hash.into())
            .unwrap();
    }

    // Jump far beyond any grace window; still the latest; still allowed
    testing_env!(VMContextBuilder::new().block_timestamp(u64::MAX).build());
    let allowed_image_hashes_far_future = setup.contract.allowed_code_hashes();

    assert_eq!(allowed_image_hashes_far_future.len(), 1);
    assert_eq!(*allowed_image_hashes_far_future[0], only_image_hash);
}

fn create_context_for_participant(account_id: &AccountId) -> VMContext {
    VMContextBuilder::new()
        .signer_account_id(account_id.clone())
        .build()
}
