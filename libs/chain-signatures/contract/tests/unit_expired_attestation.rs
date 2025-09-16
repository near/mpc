use mpc_contract::{
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
        thresholds::{Threshold, ThresholdParameters},
    },
    state::ProtocolContractState,
    VersionedMpcContract,
};

use attestation::attestation::{Attestation, MockAttestation};
use mpc_contract::primitives::{
    key_state::KeyEventId,
    participants::{ParticipantInfo, Participants},
};
use near_sdk::{
    test_utils::VMContextBuilder, testing_env, AccountId, CurveType, NearToken, PublicKey,
};
use rand::{distributions::Uniform, Rng};
use std::time::Duration;
use test_utils::attestation::p2p_tls_key;

/// Local test helper functions (copied from test_utils to avoid feature dependency)
fn gen_account_id() -> AccountId {
    const ACCOUNT_ID_LENGTH: usize = 12;
    let lower_case = Uniform::new_inclusive(b'a', b'z');
    let random_string: String = rand::thread_rng()
        .sample_iter(&lower_case)
        .take(ACCOUNT_ID_LENGTH)
        .map(char::from)
        .collect();
    format!("dummy.account.{}", random_string)
        .parse()
        .expect("Generated account ID should be valid")
}

fn bogus_ed25519_near_public_key() -> PublicKey {
    const ED25519_KEY_SIZE: usize = 32;
    let random_bytes: Vec<u8> = (0..ED25519_KEY_SIZE)
        .map(|_| rand::random::<u8>())
        .collect();
    PublicKey::from_parts(CurveType::ED25519, random_bytes)
        .expect("Random bytes should create valid public key")
}

fn gen_participants(n: usize) -> Participants {
    let mut participants = Participants::new();
    for i in 0..n {
        let (account_id, info) = (
            gen_account_id(),
            ParticipantInfo {
                url: format!("https://www.near{}.com", i),
                sign_pk: bogus_ed25519_near_public_key(),
            },
        );
        participants
            .insert(account_id, info)
            .expect("Participant insertion should succeed");
    }
    participants
}

/// Helper function to create a KeyForDomain with mock key
fn create_key_for_domain(domain_id: DomainId) -> KeyForDomain {
    const SECP256K1_UNCOMPRESSED_KEY_SIZE: usize = 64;
    let public_key = PublicKey::from_parts(
        CurveType::SECP256K1,
        vec![1u8; SECP256K1_UNCOMPRESSED_KEY_SIZE],
    )
    .expect("Mock key data should create valid public key");

    KeyForDomain {
        domain_id,
        key: PublicKeyExtended::Secp256k1 {
            near_public_key: public_key,
        },
        attempt: AttemptId::new(),
    }
}

/// **Unit test for participant kickout after expiration** - Tests expired attestation removal using VMContextBuilder.
/// This unit test demonstrates the complete kickout mechanism using direct contract calls:
/// 1. Initialize contract with 3 secp256k1 participants in Running state  
/// 2. Submit valid attestations for 2 participants at time T
/// 3. Submit expiring attestation for 1 participant with expiry at time T+10
/// 4. Fast-forward blockchain time to T+20 using VMContextBuilder
/// 5. Call verify_tee() which validates attestations against blockchain time
/// 6. verify_tee() returns false when expired attestations are detected
/// 7. Contract automatically transitions from Running to Resharing state
/// 8. Start resharing instance and have valid participants vote for completion
/// 9. Contract transitions back to Running state with filtered participant set
/// 10. Manually trigger TEE cleanup (normally done via Promise)
/// 11. Verify expired participant is removed from both protocol and TEE state
#[test]
fn test_unit_participant_kickout_after_expiration() {
    // Initialize contract in Running state with 3 participants
    const INITIAL_TIMESTAMP: u64 = Duration::from_secs(1).as_nanos() as u64;
    let context = VMContextBuilder::new()
        .block_timestamp(INITIAL_TIMESTAMP)
        .attached_deposit(NearToken::from_near(1))
        .build();
    testing_env!(context.clone());

    // Create participants and initialize contract
    const PARTICIPANT_COUNT: usize = 3;
    const THRESHOLD: u64 = 2;
    let participants = gen_participants(PARTICIPANT_COUNT);
    let threshold = Threshold::new(THRESHOLD);
    let parameters = ThresholdParameters::new(participants.clone(), threshold).unwrap();

    // Set up single secp256k1 domain and initialize contract
    let domain_id = DomainId::legacy_ecdsa_id();
    let domains = vec![DomainConfig {
        id: domain_id,
        scheme: SignatureScheme::Secp256k1,
    }];
    let keyset = {
        let epoch_id = EpochId::new(5);
        let key = create_key_for_domain(domain_id);
        Keyset::new(epoch_id, vec![key])
    };

    let mut contract =
        VersionedMpcContract::init_running(domains, 1, keyset, parameters.clone(), None).unwrap();

    // Submit valid attestations for first 2 participants
    let valid_attestation = Attestation::Mock(MockAttestation::Valid);
    let tls_key = p2p_tls_key();
    let participants_list = participants.participants();

    for (i, (account_id, _, _)) in participants_list.iter().take(2).enumerate() {
        let participant_context = VMContextBuilder::new()
            .signer_account_id(account_id.clone())
            .block_timestamp(INITIAL_TIMESTAMP)
            .attached_deposit(NearToken::from_near(1))
            .build();
        testing_env!(participant_context);

        contract
            .submit_participant_info(valid_attestation.clone(), tls_key.clone())
            .unwrap_or_else(|_| {
                panic!(
                    "Valid attestation submission should succeed for participant {}",
                    i
                )
            });
    }

    // Submit expiring attestation for third participant
    const EXPIRY_OFFSET_SECONDS: u64 = 10;
    let expiry_timestamp_seconds =
        (INITIAL_TIMESTAMP / Duration::from_secs(1).as_nanos() as u64) + EXPIRY_OFFSET_SECONDS;
    let expiring_attestation = Attestation::Mock(MockAttestation::WithConstraints {
        mpc_docker_image_hash: None,
        launcher_docker_compose_hash: None,
        expiry_time_stamp_seconds: Some(expiry_timestamp_seconds),
    });

    let (third_account, _, _) = &participants_list[2];
    let third_participant_context = VMContextBuilder::new()
        .signer_account_id(third_account.clone())
        .block_timestamp(INITIAL_TIMESTAMP)
        .attached_deposit(NearToken::from_near(1))
        .build();
    testing_env!(third_participant_context);

    contract
        .submit_participant_info(expiring_attestation, tls_key)
        .expect("Expiring attestation submission should succeed initially");

    // Verify initial state - contract should be in Running state with all participants
    let initial_tee_accounts = contract.get_tee_accounts();
    assert_eq!(
        initial_tee_accounts.len(),
        PARTICIPANT_COUNT,
        "Should have {} TEE participants initially",
        PARTICIPANT_COUNT
    );

    // Fast-forward blockchain time past the expiry
    const TIME_ADVANCE_SECONDS: u64 = 20;
    let expired_timestamp =
        INITIAL_TIMESTAMP + Duration::from_secs(TIME_ADVANCE_SECONDS).as_nanos() as u64;
    let expired_context = VMContextBuilder::new()
        .block_timestamp(expired_timestamp)
        .build();
    testing_env!(expired_context);

    // Call verify_tee() - should detect expired attestation
    let verify_result = contract.verify_tee().expect("verify_tee should not fail");
    assert!(
        !verify_result,
        "verify_tee should return false when expired attestations are detected"
    );

    // Check that contract transitioned to Resharing state
    let state = contract.state();
    let resharing_state = match state {
        ProtocolContractState::Resharing(resharing) => resharing,
        _ => panic!("Contract should be in Resharing state after expired attestation detected"),
    };

    // Verify resharing preserves previous state with all participants
    let resharing_participants = resharing_state
        .previous_running_state
        .parameters
        .participants()
        .len();
    assert_eq!(
        resharing_participants, PARTICIPANT_COUNT,
        "Resharing state should preserve previous running state with all participants"
    );

    // Start resharing instance for our single domain
    let key_event_id = KeyEventId::new(
        resharing_state.prospective_epoch_id(),
        domain_id,
        AttemptId::new(),
    );

    // Set context for the first valid participant to start resharing
    let first_participant_context = VMContextBuilder::new()
        .signer_account_id(participants_list[0].0.clone())
        .block_timestamp(expired_timestamp)
        .build();
    testing_env!(first_participant_context);

    contract
        .start_reshare_instance(key_event_id.clone())
        .expect("Should be able to start reshare instance");

    // Have the valid participants (first 2) vote for resharing completion
    for i in 0..2 {
        let (account_id, _, _) = &participants_list[i];
        let voter_context = VMContextBuilder::new()
            .signer_account_id(account_id.clone())
            .block_timestamp(expired_timestamp)
            .build();
        testing_env!(voter_context);

        contract
            .vote_reshared(key_event_id.clone())
            .expect("Valid participants should be able to vote for resharing");
    }

    // Verify contract transitioned back to Running state
    let final_state = contract.state();
    match final_state {
        ProtocolContractState::Running(_) => {
            // Contract successfully transitioned back to Running state
        }
        _ => panic!("Contract should transition back to Running state after resharing completion"),
    };

    // Manually trigger TEE cleanup (in real environment this happens via Promise)
    contract
        .clean_tee_status()
        .expect("TEE cleanup should succeed");

    // Verify expired participant was filtered out
    let final_state_after_cleanup = contract.state();
    let final_running_state = match final_state_after_cleanup {
        ProtocolContractState::Running(running) => running,
        _ => panic!("Contract should still be in Running state after cleanup"),
    };

    let final_participants = final_running_state.parameters.participants().len();
    assert_eq!(
        final_participants,
        PARTICIPANT_COUNT - 1,
        "Should have {} participants after expired participant removal",
        PARTICIPANT_COUNT - 1
    );

    // Verify TEE state cleanup - expired participant removed from TEE accounts
    let final_tee_accounts = contract.get_tee_accounts();
    assert!(
        final_tee_accounts.len() == initial_tee_accounts.len() - 1,
        "Expired participant should be removed from TEE accounts. Initial: {}, Final: {}",
        initial_tee_accounts.len(),
        final_tee_accounts.len()
    );
    assert_eq!(
        final_tee_accounts.len(),
        PARTICIPANT_COUNT - 1,
        "TEE accounts should match final participant count"
    );
}
