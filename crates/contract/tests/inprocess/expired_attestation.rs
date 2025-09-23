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
use near_sdk::{
    test_utils::VMContextBuilder, testing_env, AccountId, CurveType, NearToken, PublicKey,
    VMContext,
};
use std::time::Duration;

const SECOND: Duration = Duration::from_secs(1);
const NANOS_IN_SECOND: u64 = SECOND.as_nanos() as u64;

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

    /// Switches testing context to a given participant at a specific timestamp
    fn with_env(&mut self, account_id: &AccountId, timestamp: u64) {
        testing_env!(VMContextBuilder::new()
            .block_timestamp(timestamp)
            .signer_account_id(account_id.clone())
            .build());
    }

    /// Makes all participants vote for a given code hash at a specific timestamp
    fn vote_with_all_participants(&mut self, hash: [u8; 32], timestamp: u64) {
        for (account_id, _, _) in &self.participants_list.clone() {
            self.with_env(account_id, timestamp);
            self.contract.vote_code_hash(hash.into()).unwrap();
        }
    }
}

fn create_context_for_participant(account_id: &AccountId) -> VMContext {
    VMContextBuilder::new()
        .signer_account_id(account_id.clone())
        .build()
}

fn set_system_time(nano_seconds_since_unix_epoch: u64) {
    testing_env!(VMContextBuilder::new()
        .block_timestamp(nano_seconds_since_unix_epoch)
        .build());
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

/// **Test for grace-period expiry of older code hashes**
///
/// Verifies that when participants vote for a new image hash, the older
/// hash remains allowed only until the successor’s grace period deadline.
/// At the exact deadline both old and new hashes are valid, but immediately
/// after, only the latest remains.
#[test]
fn only_latest_hash_after_grace_period() {
    const FIRST_ENTRY_TIME: u64 = NANOS_IN_SECOND; // 1s
    const GRACE_PERIOD: u64 = 10 * NANOS_IN_SECOND; // 10s
    const DELAY: u64 = 3 * NANOS_IN_SECOND; // 3s

    let init_config = InitConfig {
        tee_upgrade_deadline_duration_seconds: Some(GRACE_PERIOD / NANOS_IN_SECOND),
        ..Default::default()
    };
    let mut setup = TestSetup::new(3, 2, Some(init_config));

    let old_hash = [1; 32];
    let successor_hash = [2; 32];

    setup.vote_with_all_participants(old_hash, FIRST_ENTRY_TIME);

    let successor_vote_time = FIRST_ENTRY_TIME + DELAY;
    setup.vote_with_all_participants(successor_hash, successor_vote_time);

    // The grace period deadline should be defined in terms of the insertion time of the successor hash.
    let deadline = successor_vote_time + GRACE_PERIOD;

    // At grace deadline → both allowed
    set_system_time(deadline);
    let _: [_; 2] = setup.contract.allowed_code_hashes().try_into().unwrap();

    // After grace → only latest
    set_system_time(deadline + 1);
    let remaining: [_; 1] = setup.contract.allowed_code_hashes().try_into().unwrap();
    assert_eq!(*remaining[0], successor_hash);
}

/// **Test for equal-timestamp precedence**
///
/// Ensures that when multiple hashes are inserted at the exact same
/// timestamp, the contract treats the *last inserted* hash as authoritative.
/// After the grace period, only this latest hash is allowed.
#[test]
fn latest_inserted_image_hash_takes_precedence_on_equal_time_stamps() {
    const INITIAL_TIME: u64 = 1;
    const GRACE_PERIOD: u64 = 10;

    let init_config = InitConfig {
        tee_upgrade_deadline_duration_seconds: Some(GRACE_PERIOD),
        ..Default::default()
    };
    let mut setup = TestSetup::new(3, 2, Some(init_config));

    let hash_1 = [1; 32];
    let hash_2 = [2; 32];
    let hash_3 = [3; 32];

    let hashes = [hash_1, hash_2, hash_3];

    for hash in hashes {
        setup.vote_with_all_participants(hash, INITIAL_TIME);
    }

    // Jump far in future
    set_system_time(u64::MAX);

    let [allowed] = setup.contract.allowed_code_hashes().try_into().unwrap();
    assert_eq!(*allowed, hash_3);
}

/// **Test for successor-based grace periods**
///
/// Confirms that a hash’s grace period is tied to the insertion time
/// of its immediate successor, not to the latest hash overall.
/// Each hash expires individually once its successor’s grace period ends.
#[test]
fn hash_grace_period_depends_on_successor_entry_time_not_latest() {
    const FIRST_ENTRY_TIME_NANOS: u64 = NANOS_IN_SECOND;
    const SECOND_ENTRY_DELAY_NANOS: u64 = 3 * NANOS_IN_SECOND;
    const THIRD_ENTRY_DELAY_NANOS: u64 = 6 * NANOS_IN_SECOND;
    const GRACE_PERIOD_NANOS: u64 = 10 * NANOS_IN_SECOND;

    let init_config = InitConfig {
        tee_upgrade_deadline_duration_seconds: Some(GRACE_PERIOD_NANOS / NANOS_IN_SECOND),
        ..Default::default()
    };
    let mut test_setup = TestSetup::new(3, 2, Some(init_config));

    let first_code_hash = [1; 32];
    let second_code_hash = [2; 32];
    let third_code_hash = [3; 32];

    test_setup.vote_with_all_participants(first_code_hash, FIRST_ENTRY_TIME_NANOS);

    let second_entry_time_nanos = FIRST_ENTRY_TIME_NANOS + SECOND_ENTRY_DELAY_NANOS;
    test_setup.vote_with_all_participants(second_code_hash, second_entry_time_nanos);

    let third_entry_time_nanos = FIRST_ENTRY_TIME_NANOS + THIRD_ENTRY_DELAY_NANOS;
    test_setup.vote_with_all_participants(third_code_hash, third_entry_time_nanos);

    // First code hash expires at successor’s deadline
    let first_hash_deadline_nanos = second_entry_time_nanos + GRACE_PERIOD_NANOS;
    set_system_time(first_hash_deadline_nanos + 1);
    assert_eq!(
        test_setup.contract.allowed_code_hashes(),
        vec![second_code_hash.into(), third_code_hash.into()]
    );

    // Second code hash expires at its own successor’s deadline
    let second_hash_deadline_nanos = third_entry_time_nanos + GRACE_PERIOD_NANOS;
    set_system_time(second_hash_deadline_nanos);
    assert_eq!(
        test_setup.contract.allowed_code_hashes(),
        vec![second_code_hash.into(), third_code_hash.into()]
    );

    set_system_time(second_hash_deadline_nanos + 1);
    assert_eq!(
        test_setup.contract.allowed_code_hashes(),
        vec![third_code_hash.into()]
    );
}

/// **Test for indefinite validity of the latest hash**
///
/// Ensures that if no successor hash is ever inserted, the most recent
/// image hash remains valid indefinitely, regardless of how far
/// blockchain time advances.
#[test]
fn latest_image_never_expires_if_its_not_superseded() {
    const START_TIME_SECONDS: u64 = 1;
    const GRACE_PERIOD_SECONDS: u64 = 10;

    let init_config = InitConfig {
        tee_upgrade_deadline_duration_seconds: Some(GRACE_PERIOD_SECONDS),
        ..Default::default()
    };
    let mut test_setup = TestSetup::new(3, 2, Some(init_config));

    let only_image_code_hash = [123; 32];
    test_setup
        .vote_with_all_participants(only_image_code_hash, START_TIME_SECONDS * NANOS_IN_SECOND);

    // Even far in the future, latest remains allowed
    set_system_time(u64::MAX);
    let allowed_image_hashes = test_setup.contract.allowed_code_hashes();

    assert_eq!(allowed_image_hashes.len(), 1);
    assert_eq!(*allowed_image_hashes[0], only_image_code_hash);
}
