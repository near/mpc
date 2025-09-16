use mpc_contract::{
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        key_state::{AttemptId, EpochId, KeyEventId, KeyForDomain, Keyset},
        test_utils::gen_participants,
        thresholds::{Threshold, ThresholdParameters},
    },
    state::ProtocolContractState,
    VersionedMpcContract,
};

use attestation::attestation::{Attestation, MockAttestation};
use near_sdk::{
    test_utils::VMContextBuilder, testing_env, AccountId, CurveType, NearToken, PublicKey,
    VMContext,
};
use std::time::Duration;
use test_utils::attestation::p2p_tls_key;

/// **Unit test for participant kickout after expiration** - Tests expired attestation removal.
/// This unit test demonstrates the complete kickout mechanism using direct contract calls:
/// 1. Initialize contract with 3 secp256k1 participants in Running state at time T=1s
/// 2. Submit valid attestations for first 2 participants at time T=1s
/// 3. Submit expiring attestation for 3rd participant with expiry at time T+10s
/// 4. Fast-forward blockchain time to T+20s using VMContextBuilder
/// 5. Call verify_tee() which detects expired attestation and returns false
/// 6. Contract automatically transitions from Running to Resharing state
/// 7. Start resharing instance and have valid participants vote for completion
/// 8. Contract transitions back to Running state with filtered participant set
/// 9. Manually trigger TEE cleanup and verify final counts reduced from 3 to 2
#[test]
fn test_unit_participant_kickout_after_expiration() {
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

    // Initialize contract with 3 participants in Running state
    let participants = gen_participants(PARTICIPANT_COUNT);
    let mut contract = {
        let parameters =
            ThresholdParameters::new(participants.clone(), Threshold::new(THRESHOLD)).unwrap();
        let keyset = Keyset::new(
            EpochId::new(5),
            vec![KeyForDomain {
                domain_id,
                key: PublicKeyExtended::Secp256k1 {
                    near_public_key: PublicKey::from_parts(CurveType::SECP256K1, vec![1u8; 64])
                        .unwrap(),
                },
                attempt: AttemptId::new(),
            }],
        );
        let domains = vec![DomainConfig {
            id: domain_id,
            scheme: SignatureScheme::Secp256k1,
        }];
        VersionedMpcContract::init_running(domains, 1, keyset, parameters, None).unwrap()
    };

    // Submit attestations: valid for first 2 participants, expiring for 3rd
    let participants_list = participants.participants();
    let tls_key = p2p_tls_key();
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);

    assert_eq!(contract.get_tee_accounts().len(), 0);

    for (account_id, _, _) in participants_list.iter().take(2) {
        submit_participant_attestation(
            &mut contract,
            account_id,
            valid_attestation.clone(),
            &tls_key,
            INITIAL_TIMESTAMP_NANOS,
        );
    }

    let expiry_seconds = INITIAL_TIME_SECONDS + EXPIRY_OFFSET_SECONDS;
    let expiring_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_time_stamp_seconds: Some(expiry_seconds),
    });
    submit_participant_attestation(
        &mut contract,
        &participants_list[2].0,
        expiring_attestation,
        &tls_key,
        INITIAL_TIMESTAMP_NANOS,
    );

    assert_eq!(contract.get_tee_accounts().len(), PARTICIPANT_COUNT);

    // Fast-forward time past expiry and trigger resharing
    let expired_timestamp =
        INITIAL_TIMESTAMP_NANOS + Duration::from_secs(POST_EXPIRY_WAIT_SECONDS).as_nanos() as u64;
    testing_env!(VMContextBuilder::new()
        .block_timestamp(expired_timestamp)
        .build());

    assert!(!contract.verify_tee().unwrap());

    let resharing_state = match contract.state() {
        ProtocolContractState::Resharing(r) => r,
        _ => panic!("Should be in Resharing state"),
    };

    // Complete resharing process
    let key_event_id = KeyEventId::new(
        resharing_state.prospective_epoch_id(),
        domain_id,
        AttemptId::new(),
    );

    testing_env!(create_context_for_participant(
        &participants_list[0].0,
        expired_timestamp
    ));
    contract.start_reshare_instance(key_event_id).unwrap();

    for (account_id, _, _) in participants_list.iter().take(2) {
        testing_env!(create_context_for_participant(
            account_id,
            expired_timestamp
        ));
        contract.vote_reshared(key_event_id).unwrap();
    }

    // Verify final state: back to Running with one less participant
    assert!(matches!(
        contract.state(),
        ProtocolContractState::Running(_)
    ));

    contract.clean_tee_status().unwrap();

    let final_running_state = match contract.state() {
        ProtocolContractState::Running(r) => r,
        _ => panic!("Should still be Running after cleanup"),
    };

    let expected_count = PARTICIPANT_COUNT - 1;
    assert_eq!(
        final_running_state.parameters.participants().len(),
        expected_count
    );
    assert_eq!(contract.get_tee_accounts().len(), expected_count);
}

fn submit_participant_attestation(
    contract: &mut VersionedMpcContract,
    account_id: &AccountId,
    attestation: Attestation,
    tls_key: &PublicKey,
    timestamp: u64,
) {
    let context = create_context_for_participant(account_id, timestamp);
    testing_env!(context);
    contract
        .submit_participant_info(attestation, tls_key.clone())
        .unwrap();
}

fn create_context_for_participant(account_id: &AccountId, timestamp: u64) -> VMContext {
    VMContextBuilder::new()
        .signer_account_id(account_id.clone())
        .block_timestamp(timestamp)
        .attached_deposit(NearToken::from_near(1))
        .build()
}
