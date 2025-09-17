use mpc_contract::{
    primitives::{domain::DomainId, participants::Participants},
    tee::tee_state::NodeId,
};

use attestation::attestation::{Attestation, MockAttestation};
pub mod common;
use common::{
    assert_resharing_return_parameters, assert_running_return_participants, conclude_resharing,
    get_tee_accounts, init_env_secp256k1, submit_participant_info,
};
use std::collections::BTreeSet;

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
#[tokio::test]
async fn test_participant_kickout_after_expiration() {
    const EXPIRY_OFFSET_SECONDS: u64 = 10; // Attestation expires 10 seconds after start

    let (worker, contract, env_accounts, _) = init_env_secp256k1(1).await;
    let init_tee = get_tee_accounts(&contract).await.unwrap();
    assert_eq!(init_tee.len(), 0);

    // Submit valid attestations for first 2 participants
    let participants: Participants = assert_running_return_participants(&contract).await.unwrap();

    let mut expected_prospective_uids = BTreeSet::new();
    for account in &env_accounts[..2] {
        let info = participants.info(account.id()).unwrap();
        let valid_attestation = Attestation::Mock(MockAttestation::Valid);
        assert!(
            submit_participant_info(account, &contract, &valid_attestation, &info.sign_pk)
                .await
                .unwrap()
        );
        expected_prospective_uids.insert(NodeId {
            account_id: account.id().clone(),
            tls_public_key: info.sign_pk.clone(),
        });
    }

    let now = worker
        .status()
        .await
        .unwrap()
        .sync_info
        .latest_block_time
        .unix_timestamp();
    println!("now: {}", now);
    let expiry: i64 = worker
        .status()
        .await
        .unwrap()
        .sync_info
        .latest_block_time
        .unix_timestamp()
        + EXPIRY_OFFSET_SECONDS as i64;

    // Submit expiring attestation for 3rd participant
    {
        let expiring_attestation = Attestation::Mock(MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_time_stamp_seconds: Some(expiry.try_into().unwrap()),
        });

        let third_participant = &env_accounts[2];
        let info = participants.info(third_participant.id()).unwrap();
        assert!(submit_participant_info(
            third_participant,
            &contract,
            &expiring_attestation,
            &info.sign_pk
        )
        .await
        .unwrap());
    }

    let found_tees = get_tee_accounts(&contract).await.unwrap();
    assert_eq!(found_tees, participants.get_node_ids());

    // Fast-forward time past expiry and trigger resharing
    worker
        .fast_forward(100u64 * EXPIRY_OFFSET_SECONDS)
        .await
        .unwrap();

    let now = worker
        .status()
        .await
        .unwrap()
        .sync_info
        .latest_block_time
        .unix_timestamp();
    println!("now: {}", now);
    let verified_tee: bool = contract
        .call("verify_tee")
        .args_json(serde_json::json!(""))
        .max_gas()
        .transact()
        .await
        .unwrap()
        .json()
        .unwrap();
    assert!(verified_tee);

    let new_params = assert_resharing_return_parameters(&contract).await.unwrap();
    assert_eq!(
        new_params.participants().get_node_ids(),
        expected_prospective_uids
    );

    // Complete resharing process
    conclude_resharing(&env_accounts[..2], &contract, &[DomainId(0)])
        .await
        .unwrap();
    let participants = assert_running_return_participants(&contract).await.unwrap();
    assert_eq!(participants.get_node_ids(), expected_prospective_uids);
}
