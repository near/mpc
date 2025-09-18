use mpc_contract::{
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
    VersionedMpcContract,
};

use assert_matches::assert_matches;
use attestation::attestation::{Attestation, MockAttestation};
use near_sdk::{
    test_utils::VMContextBuilder, testing_env, AccountId, CurveType, NearToken, PublicKey,
    VMContext,
};
use std::time::Duration;

struct TestSetup {
    contract: VersionedMpcContract,
    participants_list: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
}

impl TestSetup {
    fn new(participant_count: usize, threshold: u64) -> Self {
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
            VersionedMpcContract::init_running(domains, 1, keyset, parameters, None).unwrap()
        };

        Self {
            contract,
            participants_list,
        }
    }

    fn submit_attestation_for_node(&mut self, node_id: &NodeId, attestation: Attestation) {
        let context = create_context_for_participant(&node_id.account_id);
        testing_env!(context);
        self.contract
            .submit_participant_info(attestation, node_id.tls_public_key.clone())
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
        .attached_deposit(NearToken::from_near(1))
        .build());
    let domain_id = DomainId::default();

    let mut setup = TestSetup::new(PARTICIPANT_COUNT, THRESHOLD);

    assert_eq!(setup.contract.get_tee_accounts().len(), 0);

    // Submit valid attestations for first 2 participants
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);
    let participant_nodes: Vec<NodeId> = setup
        .participants_list
        .iter()
        .cloned()
        .take(2)
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

    assert!(!setup.contract.verify_tee().unwrap());

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

/// **Unit test for TEE cleanup of non-participants** - Tests that `clean_tee_status()` removes
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
    let mut setup = TestSetup::new(PARTICIPANT_COUNT, THRESHOLD);

    // Submit TEE info for current 2 participants (all have valid attestations)
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);
    let participant_nodes: Vec<NodeId> = setup
        .participants_list
        .iter()
        .cloned()
        .take(2)
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

fn create_context_for_participant(account_id: &AccountId) -> VMContext {
    VMContextBuilder::new()
        .signer_account_id(account_id.clone())
        .attached_deposit(NearToken::from_near(1))
        .build()
}
