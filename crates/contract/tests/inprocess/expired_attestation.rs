use contract_interface::types::{Attestation, MockAttestation};
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
use near_sdk::{test_utils::VMContextBuilder, testing_env, AccountId, NearToken, VMContext};
use std::time::Duration;

use crate::sandbox::common::IntoInterfaceType;

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
                        near_public_key: near_sdk::PublicKey::from_parts(
                            near_sdk::CurveType::SECP256K1,
                            vec![1u8; 64],
                        )
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
        self.try_submit_attestation_for_node(node_id, attestation)
            .unwrap();
    }

    fn try_submit_attestation_for_node(
        &mut self,
        node_id: &NodeId,
        attestation: Attestation,
    ) -> Result<(), mpc_contract::errors::Error> {
        let context = create_context_for_participant(&node_id.account_id);
        testing_env!(context);
        self.contract.submit_participant_info(
            attestation,
            node_id.tls_public_key.clone().into_interface_type(),
        )
    }

    /// Switches testing context to a given participant at a specific timestamp
    fn with_env(&mut self, account_id: &AccountId, timestamp: u64) {
        testing_env!(VMContextBuilder::new()
            .block_timestamp(timestamp)
            .signer_account_id(account_id.clone())
            .predecessor_account_id(account_id.clone())
            .build());
    }

    /// Makes all participants vote for a given code hash at a specific timestamp
    fn vote_with_all_participants(&mut self, hash: [u8; 32], timestamp: u64) {
        for (account_id, _, _) in &self.participants_list.clone() {
            self.with_env(account_id, timestamp);
            self.contract.vote_code_hash(hash.into()).unwrap();
        }
    }
    /// Returns the list of NodeIds for all participants
    /// Note that the account_public_key field in NodeId is None.
    /// This is because NodeId is used in contexts where account_public_key is not needed. (only TLS key is needed)
    fn get_participant_node_ids(&self) -> Vec<NodeId> {
        self.participants_list
            .iter()
            .map(|(account_id, _, participant_info)| NodeId {
                account_id: account_id.clone(),
                tls_public_key: participant_info.sign_pk.clone(),
                account_public_key: None,
            })
            .collect()
    }

    fn create_attestation_with_hash_constraint(hash: [u8; 32]) -> Attestation {
        Attestation::Mock(MockAttestation::WithConstraints {
            mpc_docker_image_hash: Some(hash),
            launcher_docker_compose_hash: None,
            expiry_time_stamp_seconds: None,
        })
    }
}

fn create_context_for_participant(account_id: &AccountId) -> VMContext {
    VMContextBuilder::new()
        .signer_account_id(account_id.clone())
        .predecessor_account_id(account_id.clone())
        .block_timestamp(near_sdk::env::block_timestamp())
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

    assert_eq!(setup.contract.get_tee_accounts().len(), PARTICIPANT_COUNT);

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
            account_public_key: Some(bogus_ed25519_near_public_key()),
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
        account_public_key: Some(bogus_ed25519_near_public_key()),
    };

    setup.submit_attestation_for_node(&third_node, expiring_attestation);

    assert_eq!(setup.contract.get_tee_accounts().len(), PARTICIPANT_COUNT);

    // Fast-forward time past expiry and trigger resharing
    const EXPIRED_TIMESTAMP: u64 =
        INITIAL_TIMESTAMP_NANOS + Duration::from_secs(POST_EXPIRY_WAIT_SECONDS).as_nanos() as u64;
    testing_env!(VMContextBuilder::new()
        .block_timestamp(EXPIRED_TIMESTAMP)
        .build());

    // verify_tee() need to be called by a participant
    testing_env!(create_context_for_participant(
        &participant_nodes[0].account_id
    ));
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
            account_public_key: Some(bogus_ed25519_near_public_key()),
        })
        .collect();
    for node_id in &participant_nodes {
        setup.submit_attestation_for_node(node_id, valid_attestation.clone());
    }

    // Add TEE account for someone who is NOT a current participant
    let removed_participant_node = NodeId {
        account_id: "removed.participant.near".parse().unwrap(),
        tls_public_key: bogus_ed25519_near_public_key(),
        account_public_key: Some(bogus_ed25519_near_public_key()),
    };

    setup.submit_attestation_for_node(&removed_participant_node, valid_attestation);

    // Verify initial state: 2 participants but 3 TEE accounts
    const INITIAL_TEE_ACCOUNTS: usize = PARTICIPANT_COUNT + 1; // 2 current + 1 stale
    let tee_accounts_before = setup.contract.get_tee_accounts().len();
    assert_eq!(tee_accounts_before, INITIAL_TEE_ACCOUNTS);

    let running_state = match setup.contract.state() {
        ProtocolContractState::Running(r) => r,
        _ => panic!("Should be in Running state"),
    };
    let participant_count = running_state.parameters.participants().len();
    assert_eq!(participant_count, PARTICIPANT_COUNT);

    // Test cleanup: should remove TEE account for non-participant
    setup.contract.clean_tee_status().unwrap();

    // Verify cleanup worked: TEE accounts reduced to match participant count
    let tee_accounts_after = setup.contract.get_tee_accounts().len();
    assert_eq!(tee_accounts_after, PARTICIPANT_COUNT);

    // State should remain Running with same participant count
    let final_running_state = match setup.contract.state() {
        ProtocolContractState::Running(r) => r,
        _ => panic!("Should still be Running after cleanup"),
    };
    let final_participant_count = final_running_state.parameters.participants().len();
    assert_eq!(final_participant_count, PARTICIPANT_COUNT);
}

macro_rules! assert_allowed_code_hashes {
    ($test_setup:expr, $blocktime_ns:expr, $expected_value:expr $(,)?) => {{
        set_system_time($blocktime_ns);
        let res: Vec<[u8; 32]> = $test_setup
            .contract
            .allowed_code_hashes()
            .iter()
            .map(|hash| *hash.clone())
            .collect();
        assert_eq!(res, $expected_value);
    }};
}

/// **Test for grace-period expiry of older code hashes**
///
/// Verifies that when participants vote for a new image hash, the older
/// hash remains allowed only until the successor’s grace period deadline.
/// At the exact deadline both old and new hashes are valid, but immediately
/// after, only the latest remains.
#[test]
fn only_latest_hash_after_grace_period() {
    const FIRST_ENTRY_TIME_NS: u64 = NANOS_IN_SECOND; // 1s
    const SECOND_ENTRY_TIME_NS: u64 = 4 * NANOS_IN_SECOND; // 1s
    const GRACE_PERIOD_NS: u64 = 10 * NANOS_IN_SECOND; // 10s

    let init_config = InitConfig {
        tee_upgrade_deadline_duration_seconds: Some(GRACE_PERIOD_NS / NANOS_IN_SECOND),
        ..Default::default()
    };
    let mut setup = TestSetup::new(3, 2, Some(init_config));

    let old_hash = [1; 32];
    let successor_hash = [2; 32];

    setup.vote_with_all_participants(old_hash, FIRST_ENTRY_TIME_NS);
    assert_allowed_code_hashes!(&setup, FIRST_ENTRY_TIME_NS, &[old_hash]);
    setup.vote_with_all_participants(successor_hash, SECOND_ENTRY_TIME_NS);
    assert_allowed_code_hashes!(&setup, SECOND_ENTRY_TIME_NS, &[old_hash, successor_hash]);

    assert_allowed_code_hashes!(
        &setup,
        SECOND_ENTRY_TIME_NS + GRACE_PERIOD_NS,
        &[old_hash, successor_hash]
    );
    assert_allowed_code_hashes!(
        &setup,
        SECOND_ENTRY_TIME_NS + GRACE_PERIOD_NS + 1,
        &[successor_hash]
    );
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
    assert_allowed_code_hashes!(&setup, INITIAL_TIME, &hashes);
    // Jump far in future
    assert_allowed_code_hashes!(&setup, u64::MAX, &[hash_3]);
}

/// **Test for successor-based grace periods**
///
/// Confirms that a hash’s grace period is tied to the insertion time
/// of its immediate successor, not to the latest hash overall.
/// Each hash expires individually once its successor’s grace period ends.
#[test]
fn hash_grace_period_depends_on_successor_entry_time_not_latest() {
    const FIRST_ENTRY_TIME_NS: u64 = NANOS_IN_SECOND;
    const SECOND_ENTRY_TIME_NS: u64 = 4 * NANOS_IN_SECOND;
    const THIRD_ENTRY_TIME_NS: u64 = 7 * NANOS_IN_SECOND;
    const GRACE_PERIOD_TIME_NS: u64 = 10 * NANOS_IN_SECOND;

    let init_config = InitConfig {
        tee_upgrade_deadline_duration_seconds: Some(GRACE_PERIOD_TIME_NS / NANOS_IN_SECOND),
        ..Default::default()
    };
    let mut test_setup = TestSetup::new(3, 2, Some(init_config));

    let first_code_hash = [1; 32];
    let second_code_hash = [2; 32];
    let third_code_hash = [3; 32];

    test_setup.vote_with_all_participants(first_code_hash, FIRST_ENTRY_TIME_NS);
    assert_allowed_code_hashes!(&test_setup, FIRST_ENTRY_TIME_NS, &[first_code_hash]);

    test_setup.vote_with_all_participants(second_code_hash, SECOND_ENTRY_TIME_NS);
    assert_allowed_code_hashes!(
        &test_setup,
        SECOND_ENTRY_TIME_NS,
        &[first_code_hash, second_code_hash]
    );

    test_setup.vote_with_all_participants(third_code_hash, THIRD_ENTRY_TIME_NS);
    assert_allowed_code_hashes!(
        &test_setup,
        THIRD_ENTRY_TIME_NS,
        &[first_code_hash, second_code_hash, third_code_hash]
    );

    assert_allowed_code_hashes!(
        &test_setup,
        SECOND_ENTRY_TIME_NS + GRACE_PERIOD_TIME_NS + 1,
        &[second_code_hash, third_code_hash]
    );

    let expiration_second_hash = THIRD_ENTRY_TIME_NS + GRACE_PERIOD_TIME_NS;
    assert_allowed_code_hashes!(
        &test_setup,
        expiration_second_hash,
        &[second_code_hash, third_code_hash]
    );

    assert_allowed_code_hashes!(&test_setup, expiration_second_hash + 1, &[third_code_hash]);
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

    assert_allowed_code_hashes!(&test_setup, u64::MAX, &[only_image_code_hash]);
}

/// **Test for nodes starting with old but valid image hashes during grace period**
///
/// This test simulates the scenario where new nodes join the network running
/// older Docker image versions that are still within their grace period.
/// It verifies that:
/// 1. Multiple image versions can coexist during their grace periods
/// 2. New nodes can successfully submit attestations with older but valid hashes
/// 3. Nodes running older images remain valid until their specific grace period expires
/// 4. The contract accepts attestations from nodes with any currently allowed hash
///
/// This validates the scenario where nodes may start up with slightly
/// older images after new ones have been voted in, as long as they're still
/// within the tee_upgrade_deadline_duration.
///
/// **Timeline Visualization (Grace Period = 15s):**
/// ```
/// Time:     T=1s   T=4s   T=7s          T=10s         T=19s   T=20s         T=22s   T=23s
///           │      │      │             │             │       │             │       │
/// v1 hash:  ●─────────────────────────────────────────────────X (expires)
/// v2 hash:         ●────────────────────────────────────────────────────────────────X (expires)
/// v3 hash:                ●────────────────────────────────────────────────────────────→ (never expires)
///           │      │      │             │             │       │             │       │
/// Events:   │      │      │             │             │       │             │       │
///          v1     v2     v3          Test all      v1 exp   Check v1      v2 exp   Check v2
///         vote   vote   vote         3 versions    @ T=19s   expired      @ T=22s   expired
///                                    still valid             only v2,v3             only v3
///
/// Grace Period Rules:
/// - v1 expires at: T=4s + 15s + 1s = T=20s
/// - v2 expires at: T=7s + 15s + 1s = T=23s  
/// - v3 never expires (no successor hash)
///
/// Note: The +1s ensures we test *after* the grace period deadline has passed.
/// Without it, the hash would still be valid exactly at the deadline timestamp.
/// ```
#[test]
fn nodes_can_start_with_old_valid_hashes_during_grace_period() {
    const INITIAL_TIME_NANOS: u64 = NANOS_IN_SECOND;
    const GRACE_PERIOD_SECONDS: u64 = 15;
    const GRACE_PERIOD_NANOS: u64 = GRACE_PERIOD_SECONDS * NANOS_IN_SECOND;
    const HASH_DEPLOYMENT_INTERVAL_NANOS: u64 = 3 * NANOS_IN_SECOND;

    let init_config = InitConfig {
        tee_upgrade_deadline_duration_seconds: Some(GRACE_PERIOD_SECONDS),
        ..Default::default()
    };
    let mut test_setup = TestSetup::new(3, 2, Some(init_config));

    let hash_v1 = [1; 32]; // Original version
    let hash_v2 = [2; 32]; // Updated version
    let hash_v3 = [3; 32]; // Latest version

    // Deploy three hash versions at 3-second intervals (T=1s, T=4s, T=7s)
    let hashes = [hash_v1, hash_v2, hash_v3];
    let mut deployment_times = Vec::new();
    let mut deployment_time = INITIAL_TIME_NANOS;

    for &hash in hashes.iter() {
        test_setup.vote_with_all_participants(hash, deployment_time);
        deployment_times.push(deployment_time);
        deployment_time += HASH_DEPLOYMENT_INTERVAL_NANOS;
    }

    // At T=10s: All three versions should be allowed (within grace periods)
    let test_time_1 = deployment_times[0] + GRACE_PERIOD_NANOS;
    assert_allowed_code_hashes!(&test_setup, test_time_1, &hashes);

    // Use existing participant nodes for testing different hash versions
    let node_ids = test_setup.get_participant_node_ids();

    // Test that nodes can submit attestations with all hash versions at T=10s
    // All attestations should succeed during grace period (current time: T=10s)
    for (node, &hash) in node_ids.iter().zip(hashes.iter()) {
        let attestation = TestSetup::create_attestation_with_hash_constraint(hash);
        test_setup.submit_attestation_for_node(node, attestation);
    }

    // Advance to T=19s: hash_v1 should expire (v2 deployed at T=4s + 15s grace = T=19s)
    // Note: v1 expires when its successor's (v2) grace period ends, not when v1's own grace period ends
    let v1_expiry_time = deployment_times[1] + GRACE_PERIOD_NANOS;

    // +1s ensures we're testing *after* expiration occurs - at T=19s the hash is still valid,
    // but at T=20s it has expired and should be filtered out by allowed_code_hashes()
    // T=20s: hash_v1 is expired. Verify that only hash_v2 and hash_v3 are allowed.
    let expected_after_v1_expiry = [hash_v2, hash_v3];
    assert_allowed_code_hashes!(&test_setup, v1_expiry_time + 1, &expected_after_v1_expiry);

    // Verify that submitting attestation with expired hash_v1 now fails
    let expired_attestation = TestSetup::create_attestation_with_hash_constraint(hash_v1);
    let result = test_setup.try_submit_attestation_for_node(&node_ids[0], expired_attestation);
    assert!(
        result.is_err(),
        "Attestation with expired hash_v1 should fail"
    );

    // Test late-joining nodes at current time T=20s (after hash_v1 expired)
    // Only hash_v2 and hash_v3 should be valid for new nodes
    // Reuse existing node_ids (nodes 2 and 3 since hash_v1 expired)
    for (node, hash) in node_ids[1..].iter().zip(expected_after_v1_expiry.iter()) {
        let late_attestation = TestSetup::create_attestation_with_hash_constraint(*hash);
        test_setup.submit_attestation_for_node(node, late_attestation);
    }

    // Advance to T=22s: hash_v2 should expire (v3 deployed at T=7s + 15s grace = T=22s)
    let v2_expiry_time = deployment_times[2] + GRACE_PERIOD_NANOS;
    assert_allowed_code_hashes!(&test_setup, v2_expiry_time + 1, &[hash_v3]);

    // Verify that only the latest hash is now accepted
    // Reuse the third node (index 2) for final validation
    let final_attestation = TestSetup::create_attestation_with_hash_constraint(hash_v3);
    // This should succeed since hash_v3 is the only remaining valid hash
    test_setup.submit_attestation_for_node(&node_ids[2], final_attestation);
}
