use std::time::Duration;

use crate::config::{NodeStatus, ParticipantStatus};
use crate::indexer::fake::participant_info_from_config;
use crate::indexer::participants::ContractState;
use crate::p2p::testing::PortSeed;
use crate::providers::PublicKeyConversion;
use crate::tests::DEFAULT_BLOCK_TIME;
use crate::tests::{
    get_keyshares, request_signature_and_await_response, IntegrationTestSetup,
    DEFAULT_MAX_PROTOCOL_WAIT_TIME,
};
use crate::tracking::AutoAbortTask;
use mpc_contract::node_migrations::{BackupServiceInfo, DestinationNodeInfo};
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use mpc_contract::primitives::test_utils::bogus_ed25519_public_key;
use mpc_contract::state::ProtocolContractState;
use near_o11y::testonly::init_integration_logger;
use near_time::Clock;

/// Runs a cluster of 3 nodes, but with only 2 participants.
/// Two nodes of the cluster are assigned the same account id.
/// Each node has its own home directory and tls key.
/// After the conclusion of the key initialization and passing of a sanity check, the participant
/// set will be forcefully changed.
#[tokio::test]
async fn test_onboarding() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 2;
    const THRESHOLD: usize = 2;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut account_ids: Vec<_> = (0..NUM_PARTICIPANTS)
        .map(|i| format!("test{}", i).parse().unwrap())
        .collect();
    account_ids.push(format!("test{}", 0).parse().unwrap());
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        account_ids,
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::ONBOARDING_TEST,
        DEFAULT_BLOCK_TIME,
    );

    let home_dir_first = setup.configs.first().unwrap().home_dir.clone();
    let local_encryption_key_first = setup.configs.first().unwrap().secrets.local_storage_aes_key;

    // Initialize the contract with the first two nodes
    let mut initial_participants = setup.participants.clone();
    let onboarding_participant = initial_participants.participants.pop().unwrap();

    let onboarding_participant_keyshare_sender =
        setup.configs.last().unwrap().keyshares_sender.clone();
    let destination_node_info = participant_info_from_config(&onboarding_participant);
    let destination_node = {
        let signer_account_pk = setup
            .configs
            .last()
            .unwrap()
            .secrets
            .persistent_secrets
            .near_signer_key
            .verifying_key()
            .to_near_sdk_public_key()
            .unwrap();

        DestinationNodeInfo {
            signer_account_pk,
            destination_node_info: destination_node_info.clone(),
        }
    };

    let domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Secp256k1,
    };

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(initial_participants);
        contract.add_domains(vec![domain.clone()]);
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("timout waiting for running state");

    tracing::info!("we are in running state");

    // Sanity check.
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    let ProtocolContractState::Running(running) = setup.indexer.contract_mut().await.state.clone()
    else {
        panic!("expect running")
    };
    let found_init_partcipants = running.parameters.participants();
    let init_participant_info = found_init_partcipants
        .info(&onboarding_participant.near_account_id)
        .unwrap();

    tracing::info!("Starting onboarding test - setting backup info");
    {
        // smart contract changes
        let mut contract = setup.indexer.contract_mut().await;
        assert!(matches!(&contract.state, ProtocolContractState::Running(_)));
        contract.migration_service.set_backup_service_info(
            onboarding_participant.near_account_id.clone(),
            BackupServiceInfo {
                public_key: bogus_ed25519_public_key(),
            },
        );
        contract.migration_service.set_destination_node_info(
            onboarding_participant.near_account_id.clone(),
            destination_node,
        );
    }

    tracing::info!("Starting onboarding test - sending keyshares");
    {
        let ProtocolContractState::Running(running) = &setup.indexer.contract_mut().await.state
        else {
            panic!("expect running");
        };
        let keyset = &running.keyset;
        let keyshares = get_keyshares(home_dir_first, local_encryption_key_first, &keyset)
            .await
            .unwrap();
        onboarding_participant_keyshare_sender
            .send(keyshares)
            .unwrap();
    }
    tracing::info!("Sent keyshares");

    // wait for contract state change
    setup
        .indexer
        .wait_for_contract_state(
            |state| {
                matches!(
                    state.node_status(
                        &onboarding_participant.near_account_id,
                        &onboarding_participant.p2p_public_key
                    ),
                    ParticipantStatus::Active(NodeStatus::Active)
                )
            },
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let ProtocolContractState::Running(running) = setup.indexer.contract_mut().await.state.clone()
    else {
        panic!("expect running")
    };

    let found_partcipants = running.parameters.participants();
    let current_participant_info = found_partcipants
        .info(&onboarding_participant.near_account_id)
        .unwrap();
    assert_eq!(*current_participant_info, destination_node_info);
    assert_ne!(current_participant_info, init_participant_info);

    // as a precaution, disable the first node
    setup.indexer.disable(0.into()).await;

    // Sanity check. Since we are in full-threshold, we have confirmation that the new node is up
    // and running.
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user2",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user3",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());
}
